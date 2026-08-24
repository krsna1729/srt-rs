# Reading a result row: where the bottleneck actually is

**Audience:** anyone doing post-sweep analysis on `srt-bench` output. This
is a reference, not a narrative — jump to the section you need.

A cell in the sweep produces two rows, one per role (`caller`, `listener`),
sharing every config column. The measurement columns tell two different
stories depending which row you're reading, and conflating them is how
several wrong conclusions got published earlier in this project (see
[dead-timers-2026-08-23.md](dead-timers-2026-08-23.md) and
[split-role-cli.md](plans/split-role-cli.md) for two worked postmortems).
This doc exists so the next anomaly gets chased with the right column
instead of a hunch.

## The columns, grouped by what they tell you

### Configuration (identical on both rows)

`runtime encryption ingress promotion cookie batch sock_buf cpus pin link_* workers
recv_* send_* conns connect_cc bond bitrate rep secs` — the axes the cell
was run at. `encryption` is `plain`, `128`, `192`, or `256`. `secs` is the
stream length both roles agree on; it is not
`elapsed_s` (see below).

### What actually happened, protocol level

| column | meaning | who reports it meaningfully |
|---|---|---|
| `established` | connections that reached `Connected` | both, should match |
| `torn_down` | connections that ended by something *other* than the sender's ordered SHUTDOWN — an idle timeout, an error | **both, independently** — see below |
| `pkt_sent` / `core_total` | packets this role's `SrtConnection` counted (original sends on caller, receives on listener) | both |
| `sec_a` | retransmits (caller) / packets lost (listener) | role-dependent, same column |
| `sec_b` | packets in loss list (caller) / duplicates (listener) | role-dependent |
| `rtt_ms` | round-trip time as measured by the listener's ACKs | listener only; the caller's is usually 0 (RTT is never wired into the caller path) |

### Kernel, not protocol

| column | meaning |
|---|---|
| `udp_rcvbuf_err` | datagrams dropped because this process's UDP receive queue was full |
| `udp_in_err` | datagrams dropped for any other kernel reason (bad checksum, etc.) |
| `udp_no_ports` | datagrams arriving at a port nobody was listening on |

These come from `/proc/net/snmp`, delta'd against a baseline taken before
any socket exists, so they are per-process for that run's lifetime — not
host-wide. **This is the one thing that distinguishes "the protocol lost
it" from "the kernel threw it away before the protocol ever saw it."** A
cell with heavy loss and `sec_a = 0` on the listener is not a mystery:
check `udp_rcvbuf_err` first. That single check found the actual cause of
what had been recorded as an unexplained ~50% loss with no retransmits —
1.27M receive-queue overflows, invisible anywhere else in the row.

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
| `offer%` | caller `core_total` ÷ target packet count | **Did the sender keep up with the configured rate?** Target is `conns × bitrate × secs ÷ (8 × PAYLOAD_SIZE)`. Below 100%: the load generator itself is the constraint — add `--workers`, or check for a stuck deadline. |
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
   count / bitrate.
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
