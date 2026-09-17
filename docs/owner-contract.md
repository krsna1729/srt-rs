# The shared-Owner contract

**Status:** frozen at the semantic level. Internals stay open.

This is what an embedding application may rely on when it drives a Compio
`Owner` (`srt_transport::compio::Owner`). It is deliberately written against
*observable semantics*, not against today's structures, so that batching, GSO,
a different lane implementation, a different heap representation, or different
io_uring flags can land without changing any clause here.

Everything below is pinned by tests, listed in [Test map](#test-map). A clause
without a test is a claim, not a contract.

## Scope

An `Owner` owns one shared listener UDP socket and one shared caller UDP socket
and drives many logical SRT sessions over them, with a fixed number of runtime
engines rather than one per session. It is the unit of thread affinity,
capacity, fault domain, and shutdown.

```text
application (one thread / one runtime)
  └── Owner
        ├── listener side  : one UDP socket, one ingress admission table
        ├── caller side    : one UDP socket, one logical-caller table
        ├── TX pool        : fixed K slots, fixed K lanes
        └── RX path        : bounded reads into protocol-owned state
```

## Frozen

### 1. Ownership and thread affinity

An `Owner` is owned by exactly one application thread. It is neither `Send` nor
`Sync` across owners, it holds no global state, and it never spawns work onto a
thread the application did not give it. Every session's protocol state is owned
by the tables the `Owner` owns: the application never holds a connection
alongside the `Owner` that drives it.

### 2. Fixed capacity, declared at construction

`Owner::new(tx_capacity)` / `Owner::new_with_ceiling(tx_capacity, wire_ceiling)`
fix the number of concurrently outstanding outbound datagrams (K) and the
maximum wire length of one datagram. Neither grows at runtime. `K` is a ceiling
on outstanding submissions, not a target: an owner with K lanes may have any
number of sessions.

`queued + in-flight + completed-not-yet-reaped <= K` holds at every instant, and
the pool reports its own peak through `TxPoolSnapshot::high_water`.

### 3. Reserve before materialize

Every outbound datagram reserves final transport storage *and* a TX lane before
the protocol materializes a single byte into it. Therefore:

* a capacity refusal leaves the protocol output untouched and queued, so nothing
  is dropped without being accounted;
* a datagram that the protocol has materialized is irrevocably submitted: it
  cannot fail afterwards for capacity reasons, and its buffer returns to the pool
  exactly once, on completion.

This ordering is why `DatagramSlot::commit` is infallible and why the protocol's
`poll_output_into` is the submission boundary (see clause 11).

### 4. Bounded service

`Owner::service(now, budget)` performs at most the work `budget` declares, per
axis: `max_completions`, `max_rx_packets`, `max_rx_bytes`, `max_actions`,
`max_tx_packets`, `max_tx_bytes`. Zero on an axis means zero work on that axis —
never "unlimited". The visit never blocks on I/O and never waits for a
completion; completions are reaped only when already ready.

The returned `OwnerServiceReport` describes *that visit only*. Cumulative values
are separate, and callers accumulate deltas themselves.

### 5. Timers belong to the protocol

The `Owner` invents no timers. Deadlines come from protocol outputs
(`SetTimer`/`ClearTimer`) applied to the transport's timer store, and a visit
fires only deadlines that have actually elapsed. Therefore a session's pacing,
ACK/NAK cadence, keepalive, handshake retry, inactivity timeout, shutdown retry,
and sender retransmission timeout are all protocol decisions; the transport only
honours them.

### 6. Explicit continuation, never hidden queueing

Work a visit does not finish stays visible: the report says whether work remains
(`work_remaining`, `budget_exhausted`, `next_deadline_us`), `has_pending_work`
answers the same question for the next visit, and `time_until_next_deadline` says
when it is worth running again. Nothing is moved into an unbounded queue to be
forgotten: a datagram that could not be submitted stays queued in the protocol,
bounded by the protocol's own output limits.

### 7. Fault poisoning is total and latched

Any `OwnerFault` stops new admission and new TX submission on that `Owner`. The
first fault is latched and never cleared; `Owner::fault()` reports it. A faulted
`Owner` is not a quiet socket and not a reduced-capacity steady state: `listen`
and `connect` refuse, the TX sink refuses new protocol output, and RX maintenance
stops. Already-submitted work may still be reaped, so a faulted owner can still
return its slots and shut down.

### 8. Admission and backpressure are explicit

Sessions enter through bounded tables with declared capacity (peers, half-open
peers, established peers, peers per source IP; logical callers; the caller pool).
A refusal is a typed outcome the application sees, never a silent drop, and no
table grows without a bound. A slow or overloaded peer leaves backpressure in
the protocol's own flow control, not in an unbounded transport queue.

### 9. Completion ownership

The `Owner` owns completions until it reaps them; the application never reaches
into the TX path. Each reaped slot returns to the pool exactly once. Every
completion is classified:

* success (bytes written equal the materialized length);
* a short send or a structural send failure — an invariant violation that faults
  the whole `Owner`;
* a peer-local or transient failure — accounted once, attributed to the logical
  session/leg, never retried inside the transport, and never fatal to healthy
  siblings sharing the socket.

Attribution is a logical session identity, not a socket address: several
sessions and group legs can share one remote endpoint.

### 10. Bounded close

`shutdown_and_drain(timeout)` stops admission, drains in-flight work, and reports
whether quiescence was actually reached inside the deadline. It never fabricates
quiescence: a timeout leaves ownership exactly as it was and says so. No detached
task retains the socket after the owner is gone, and receive tasks join inside
the same bounded teardown.

### 11. Telemetry meanings

* `OwnerServiceReport` fields are per-visit deltas.
* `tx_packets_submitted` counts datagrams that reached the submission boundary
  (reserved, materialized, handed to a lane) — it is not an application-accepted
  count and not a kernel-completion count.
* TX class counters partition exactly those submissions:
  `sum(classes) == tx_packets_submitted` for every visit, and the class of a
  datagram is decided by the protocol, not inferred from bytes.
* `TxPoolSnapshot` reports `capacity`, `free`, `high_water` (monotonic peak of
  simultaneously checked-out slots, never above `capacity`), and `exhaustions`.
* First-submit lateness is measured from the source's own due instant for a first
  transmission to the point the datagram is handed to a TX lane. It is not a
  completion-time metric, and per-lane asynchronous latency is explicitly outside
  it. Control datagrams and retransmissions have no source due instant and
  contribute no sample.

## Not frozen

These are implementation choices an embedding application must not depend on;
each may change without notice while every clause above still holds:

* `TxPool`'s representation (today: a `Vec<Vec<u8>>` of pre-allocated slots) and
  its slot size policy.
* The TX lane implementation (today: fixed Compio tasks with a same-thread
  job handoff) and the number of lanes relative to `K`.
* The deadline heap and ready-queue representations on either side.
* io_uring flags, batching, and whether datagrams are submitted individually or
  as a batch.
* The concrete timer store type, as long as its semantics are those of
  clause 5.
* The RX path's mechanism (raw `recvfrom` versus a persistent multishot
  consumer), as long as RX budgets and truncation accounting are those of
  clauses 4 and 11.
* The layout of any protocol-owned structure.

## Test map

All names below are in `crates/srt-transport/src/runtimes/compio.rs`'s test module
unless a path is given.

| Clause | Pinned by |
|---|---|
| 1 ownership | Not `Send`/`Sync`: enforced by the type; `owner_sibling_isolation` |
| 2 fixed capacity | `owner_tx_bounded_concurrency_and_pool_exhaustion`, `owner_tx_pool_alloc_and_recycling`, `tx_pool_high_water_tracks_the_peak_and_never_exceeds_capacity` |
| 3 reserve before materialize | `tx_pool_exhaustion_leaves_protocol_datagram_pending`, `owner_connects_transfers_data_and_tracks_resources` |
| 4 bounded service | `rx_budget_is_exact_and_zero_means_zero`, `service_with_zero_completion_budget_reaps_nothing`, `service_returns_tx_buffers_and_updates_completion_stats`, `one_action_budget_bounds_whole_caller_visit` |
| 5 protocol-owned timers | `owner_wake_includes_caller_pool_attempt_deadline`, `crates/srt-transport/tests/tail_recovery.rs` |
| 6 explicit continuation | `tx_pool_exhaustion_leaves_protocol_datagram_pending`, `owner_tx_bounded_concurrency_and_pool_exhaustion` |
| 7 fault poisoning | `managed_rx_stream_failure_faults_the_owner`, `rx_consumer_fault_stops_rx_maintenance_and_tx`, `owner_fault_gates_listen_and_connect_through_public_apis`, `failed_attach_does_not_freeze_the_owner`, `a_dead_tx_lane_poisons_the_owner_and_cannot_continue_at_reduced_capacity` |
| 8 admission/backpressure | `owner_rejects_session_with_incompatible_wire_ceiling`, `owner_wake_includes_caller_pool_attempt_deadline` |
| 9 completion ownership | `service_returns_tx_buffers_and_updates_completion_stats`, `tx_failure_event_reports_the_logical_attribution`, `owner_sibling_isolation` |
| 10 bounded close | `shutdown_and_drain_reaps_in_flight_to_quiescence`, `shutdown_timeout_does_not_fabricate_quiescence`, `shutdown_verdict_requires_rx_quiescence`, `a_dead_tx_lane_poisons_the_owner_and_cannot_continue_at_reduced_capacity` |
| 11 telemetry meanings | `report_tx_class_total_matches_submitted_packets_every_visit`, `tx_class_delta_reports_only_this_visits_submissions`, `first_submit_lateness_samples_only_first_transmission_data_with_a_due_instant`, `first_submit_lateness_measures_a_real_application_submission`, `tx_pool_high_water_tracks_the_peak_and_never_exceeds_capacity`, `rx_stats_expose_both_sides`, `rx_session_totals_report_live_sessions_and_survive_retirement`, `rx_session_totals_are_none_without_an_attached_side`, `rx_session_totals_include_bonded_group_legs` |

Row-level evidence is gated separately, in `cargo xtask qualify`: a
qualification row must decompose its wire submissions
(`sum(tx_class_*) == tx_class_total == tx_submitted_wire`) and carry the
first-submit lateness fields. That gate is the executable form of clause 11 for
published results.
