# Reading a result row: where the bottleneck actually is

**Audience:** anyone doing post-sweep analysis on `srt-bench` output. This
is a reference, not a narrative — jump to the section you need.

A cell in the sweep produces two rows, one per role (`caller`, `listener`),
sharing every config column. The measurement columns tell two different
stories depending which row you're reading, and conflating them is how
several wrong conclusions got published earlier in this project. The
split-role analysis in [split-role-cli.md](plans/split-role-cli.md) is one
worked example.
This doc exists so the next anomaly gets chased with the right column
instead of a hunch.

## The columns, grouped by what they tell you

### Configuration (identical on both rows)

`runtime encryption ingress promotion cookie batch recv_rounds
would_block_policy sock_buf_requested_bytes sock_*_effective_*_bytes cpus pin
link_* workers recv_* send_* conns
logical_streams source_streams connect_cc bond source_bps srt_bw_mode
source_backlog_ms datapath_q_horizon_ms retry_horizon_ms rep secs` — the axes
the cell was run at. `cpus` is the role's effective affinity mask;
`recv_cpus` / `send_cpus` preserve the requested split-role placement on both
rows. `encryption`
is `plain`, `128`, `192`, or `256`. `secs` is the stream length both roles
agree on; it is not `elapsed_s` (see below).

**`source_bps` is the application workload, not SRT's pacing ceiling.**
They used to be one column called `bitrate`, and because the sender had no
clock of its own — it pushed payload whenever `SRTO_MAXBW` pacing allowed
— "did the sender offer its configured load?" was a question about the
ceiling that produced the load, and could not fail. The two are now
separate: `source_bps` is the payload rate each source produces, and
`srt_bw_mode` / `srt_maxbw_bps` / `srt_inputbw_bps` / `srt_oheadbw_pct`
record the pacing policy and what it resolved to. A cell with an 8 Mbit/s
source and a 4 Mbit/s ceiling is a legitimate diagnostic configuration; it
shows up as roughly 50% `offer%`, not as a quietly halved target.

**Three cardinalities, not one.** `conns` is *physical* connections,
`logical_streams` is what a group-aware listener admits, and
`source_streams` is how many independent payload producers the sender ran.
They are equal unless the cell is bonded, where a two-leg group is two
physical connections carrying one stream from one source. Rates are
computed against `source_streams`; caller establishment is measured
against `conns` and listener establishment against `logical_streams`.

A result file written before this split is rejected by name rather than
silently reinterpreted: its `bitrate` column cannot be read as either
quantity.

`sock_buf_requested_bytes` is likewise distinct from the effective receive
and send ranges the kernel granted. The min/max columns are scoped to all
sockets created by that row's process; a range exposes non-uniform grants
instead of silently selecting one socket.

### What actually happened, protocol level

| column | meaning | who reports it meaningfully |
|---|---|---|
| `established` | connections that reached `Connected` | both, should match |
| `torn_down` | connections that ended by something *other* than the sender's ordered SHUTDOWN — an idle timeout, an error | **both, independently** — see below |
| `pkt_sent` / `core_total` | packets this role's `SrtConnection` counted (original sends on caller, receives on listener) | both |
| `sec_a` | retransmits (caller) / packets lost (listener) | role-dependent, same column |
| `sec_b` | packets in loss list (caller) / duplicates (listener) | role-dependent |
| `rtt_ms` | round-trip time as measured by the listener's ACKs | listener only; the caller's is usually 0 (RTT is never wired into the caller path) |

### The application source, not the protocol

Only the caller row carries these; a listener has no workload to produce.

| column | meaning |
|---|---|
| `src_generated` | payload opportunities the source clock produced, on its own cadence |
| `src_accepted` | opportunities SRT took |
| `src_refusal_polls` | send attempts that found SRT unwilling. **Poll-rate dependent** — a runtime that wakes more often reports more of these for identical backpressure, so it is a diagnostic, not a cross-runtime metric |
| `src_blocked_streaks` | contiguous episodes of backpressure, one per episode however long. Poll-rate independent, so this is the one to compare across runtimes |
| `source_backlog_ms` / `src_backlog_cap` | the configured backlog policy, and the packet capacity it resolved to at this source rate |
| `src_backlog_hwm` | the deepest any one connection's pending source got |
| `src_overflow` | opportunities dropped because the backlog was full |

The backlog is bounded by *rate*, never by run duration, so a longer
benchmark cannot hide a growing backlog: a source the transport cannot
service overflows within a second or two and says so. **A clean cell
requires `src_overflow == 0`**, which is what makes "the sender offered
its load" a claim that can fail.

`src_backlog_hwm` well below `src_backlog_cap` with zero overflow is a
source being serviced comfortably. A high-water mark pinned at capacity
with overflow climbing is the transport failing to carry the configured
workload — cross-reference `srt_maxbw_bps` before blaming the runtime,
since a pacing ceiling below the source rate produces exactly this.

### Kernel, not protocol

| column | meaning |
|---|---|
| `udp_rcvbuf_err` | datagrams dropped because this process's UDP receive queue was full |
| `udp_in_err` | datagrams dropped for any other kernel reason (bad checksum, etc.) |
| `udp_no_ports` | datagrams arriving at a port nobody was listening on |

These come from host-wide `/proc/net/snmp` counters, delta'd over each role's
process lifetime. On an isolated benchmark host that window attributes the
drops to the cell; unrelated UDP traffic is therefore a host-validity concern.
**This is the one thing that distinguishes "the protocol lost it" from "the
kernel threw it away before the protocol ever saw it."** A
cell with heavy loss and `sec_a = 0` on the listener is not a mystery:
check `udp_rcvbuf_err` first. That single check found the actual cause of
what had been recorded as an unexplained ~50% loss with no retransmits —
1.27M receive-queue overflows, invisible anywhere else in the row.

`recv_packets`, `recv_syscalls`, and `datagrams_per_syscall` describe the
Tokio shared-pool receive service.

`timer_late_p50_bucket_us` through `timer_late_p99_bucket_us` come from a
fixed power-of-two histogram, so what they report is the **upper edge of
the bucket** the percentile falls in — not the percentile itself, hence
the name — clamped to `timer_late_max_us`. Read them as upper bounds. (An
earlier version left them unclamped, which produced a "p99" larger than
the largest lateness actually measured.)

`retry_horizon_ms`, `retry_count`, `retry_cap_per_queue`,
`retry_total_cap`, `retry_peak_depth_max`, `would_block`,
`retry_overflow`, and `local_dropped` describe benchmark-owned outbound
work the harness is holding on to. `local_dropped` is the **total**
datagrams dropped locally; `retry_overflow` is one *reason* inside that
total, so never add the two. A clean pair requires `local_dropped = 0`.

### Resource cost

`elapsed_s cpu_user_ms cpu_sys_ms peak_rss_kb` — this process's own
wall/CPU/memory for the run. `elapsed_s` is wall time for *this* process,
which is why a caller and listener in the same cell can show different
values: under the ordered-close protocol they should now match closely
(within the ramp-up/teardown margin), and a caller that noticeably
outlives its listener again is the same race that used to produce
`udp_no_ports` bursts — see "Symptom: `udp_no_ports` after a run" below.

## `report`'s derived columns, and what each one is actually asking

`srt-bench report` computes seven figures a raw row does not give you
directly. Each answers a different question — use the one that matches
what you're diagnosing, not the first one that looks plausible.

| column | formula | question it answers |
|---|---|---|
| `offer%` | caller `core_total` ÷ source target packets | **Did the sender offer the configured workload?** Target is `source_streams × (source_bps ÷ 8) × secs ÷ PAYLOAD_SIZE` — payload bytes only, because the *application* does not produce SRT headers. (It used to divide by `PAYLOAD_SIZE + SRT_HEADER_SIZE`, `SRTO_MAXBW`'s wire unit, which measured the pacing ceiling against itself.) Below 100% means either the load generator is the constraint — add `--workers`, or check for a stuck deadline — or the SRT bandwidth policy cannot carry the source rate; `srt_maxbw_bps` and `src_blocked_streaks` tell you which. |
| `good%` | listener `core_total` ÷ target | **Did the receiver end up with the full stream, in absolute terms?** Ignores what the sender actually offered — useful for "did we hit the target rate" but conflates sender and listener shortfalls if read alone. |
| `deliv%` | listener `core_total` ÷ caller `core_total` | **Of what was actually sent, how much arrived?** This is the transport's own delivery ratio. High `deliv%` with low `offer%` means the sender, not the transport, is the story. |
| `lost` | listener `sec_a` | Loss the *protocol* detected (and presumably tried to recover from). Compare against `rcvbuf_drop` — see below. |
| `rcvbuf_drop` | listener `udp_rcvbuf_err` | Loss the *kernel* caused before the protocol ever saw the packet. `lost` cannot include this by construction: a NAK requires observing a sequence-number gap, and an overflowed queue means the packet just never arrived to create one. |
| `torn_c` / `torn_l` | caller / listener `torn_down`, separately | How many connections ended abnormally, from each side's own point of view. **Not always equal** — a connection can look torn-down to its sender (no ACKs arrived, its own idle timer fired) while its listener never noticed anything wrong, or vice versa. Report both; do not sum them into one number, since which side saw the tear-down is itself diagnostic. |
| `rtt_ms` | median listener `rtt_ms` | Listener-observed RTT. Rises with queueing before it rises with configured `--link-delay`, so a jump here at constant `--link-*` settings is itself a load signal, not just a latency one. |

`offer%` and `good%` are computed against the same denominator; the
difference between them is entirely `deliv%`. If you only remember one
thing: **`offer%` tells you about the sender, `good%`/`deliv%` tell you
about everything downstream of it, and a low `good%` with a healthy
`offer%` and `deliv%` near 100% means the target rate itself was simply
higher than the transport could carry — that's a real ceiling, not a bug
to chase.**

## Diagnostic order, cheapest check first

When a cell's delivery is bad, check in this order — each step is a single
column comparison and rules out an entire category of explanation:

1. **`offer%` < ~95%?** The sender didn't offer the configured load. Stop
   here — nothing downstream can be blamed for traffic that never left.
   Fix: more `--workers`, check for the connection's own send loop
   stalling on its deadline, check `--connect-concurrency`.
2. **`offer%` healthy, `rcvbuf_drop` > 0?** The kernel is dropping
   datagrams on the listener's socket before the protocol sees them. This
   is a *listener capacity* problem, not a protocol one. Fix: more
   `--recv-workers` (pooled ingress is single-threaded per socket-group by
   default — see [split-role-cli.md](plans/split-role-cli.md)), larger
   `--sock-buf`, or accept it as the actual ceiling at this connection
   count / source rate.
3. **`offer%` and `rcvbuf_drop` both clean, `lost` > 0?** Now it's
   protocol-level loss — genuine network conditions (`--link-loss`), or a
   retransmission/pacing issue worth investigating in the transport
   itself, not the harness.
4. **Everything above clean but `torn_c` or `torn_l` > 0?** Some
   connections didn't survive the run even though aggregate throughput
   looks fine — a per-connection problem (e.g. one connection's task
   starved of scheduler time) rather than a systemic one. Cross-reference
   which side saw it: `torn_c > 0, torn_l = 0` means the sender's own view
   of a connection went idle (commonly downstream of #2 above — no ACKs
   arrived because the listener dropped them), not that the listener
   considered anything wrong.
5. **Everything clean, `good%` still short of 100%?** The target rate
   exceeded what this configuration can carry, cleanly. That's the actual
   ceiling for this cell — the number you were sweeping to find.

## Worked examples from this project's own false starts

**"Delivery 139%."** Not a transport bug: a caller row survived from a
killed run, resume didn't require both roles present, and a second caller
row got appended on retry. `report` medianed each side independently and
divided a complete listener figure by the median of one truncated and one
complete caller row. Fixed by pairing roles per rep and requiring both for
resume — but the general lesson is that any `report` ratio should be
sanity-checked for `estab` matching between the two rows before trusting
it as a percentage.

**"Offer 0.0% from a sender that sent two million packets."** A formula
bug: `offered = sent − retransmits`, but `total_sent` already excludes
retransmits at the source, so this double-subtracted and floored at zero
under heavy loss. The fix was `offer% = sent ÷ target`, no subtraction —
but the general lesson is: know whether a protocol counter is cumulative
or exclusive before combining it with another one.

**"Pooled ingress collapses above `--workers 2`."** Not a harness bug —
`shared-pool:K` binds K ports on **one** thread by design, the control
strategy that isolates "fewer wakeups" from "kernel demux". The sender
simply got strong enough to cross that ceiling; `rcvbuf_drop` going from
~0 to 1.6M at the same cell is what proved it, and `--recv-workers`
(shards the pool sockets across threads) is what removed it.

**`udp_no_ports` after a run.** The listener exited before the sender
finished, so the sender's last packets landed on a closed port. Root
cause: the harness used to guess a fixed teardown timeout instead of
signalling the sender-then-listener order explicitly. Fixed by an ordered
SIGTERM handshake — see `crate::shutdown` and `SrtConnection::disconnect`.
If this reappears, check `elapsed_s` divergence between the two rows
first.

## What isn't captured yet

- `report`'s columns are per-cell medians; nothing here characterizes
  variance across reps within a cell. A single-rep sweep (the default so
  far) cannot distinguish a stable 80% ceiling from a bimodal 60%/100%
  split that happens to median at 80%.
- No sustained (over the run's duration) view — every number here is a
  final total or a snapshot, not a time series. A cell that degrades in
  its last two seconds looks identical to one that was bad throughout.
