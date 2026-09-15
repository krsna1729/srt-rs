# Raw io_uring vs Compio opportunity decision (dc83aa2)

## Question

Would a hand-rolled native io_uring Owner (bypassing Compio) save enough
CPU to justify building and maintaining a second runtime backend?

## Evidence against building it now

1. TX attribution (`docs/results/compio-tx-allocs-8af34c8.txt`): srt-transport
   orchestration in `service()` is 0.000 alloc/op. The 1.000/op floor is
   Compio's own `send_to` op state; the 2.000/op is kernel-timeout waits
   per idle epoch, not per datagram at load. A native backend could at
   most remove Compio's ~1 op allocation — it cannot remove the kernel
   send itself.
2. RX substrate blocked by kernel: `IORING_REGISTER_PBUF_RING` returns
   EINVAL on this host's Ubuntu Noble 6.8.0-139-generic (strace-proven,
   valid params, page-aligned, power-of-two entries). A native
   multishot-receive prototype cannot even register its buffer ring here;
   it would measure the fallback path, not the opportunity.
3. Qualification frontier (`qual-compio-frontier.md`): 100x100 clean at
   ~55k pps sender-side; the 600 row is INVALID (receiver timeout-start
   skew, rerun pending) and is not evidence for or against op cost.
   No valid same-workload shared-Owner A/B exists yet.
4. Cost: a native backend duplicates driver setup, buffer-ring management,
   completion reaping, cancellation, and Poll-fallback — all already owned
   by Compio and covered by its tests.

## Decision

**Stay Compio. Do not build a native io_uring Owner in this PR.**
Revisit only with: (a) a kernel where PBUF_RING registers (HWE 7.0
installed, reboot pending), AND (b) two-process shared-Owner evidence
showing per-send op cost is the binding constraint at the shard frontier.
Neither condition holds today.

## Benchmark status

No benchmark-only raw-vs-Compio sweep was run: with PBUF_RING rejected,
any "raw" UDP send loop would compare raw syscalls against Compio managed
ops without SRT framing — the same invalid comparison that got
`raw_vs_compio_driver` removed. The honest sweep needs the HWE kernel
first; recorded here as an explicit non-blocking deferral.
