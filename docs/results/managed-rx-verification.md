# Managed multishot RX: verification on a qualified kernel

## Why this exists

`IORING_REGISTER_PBUF_RING` fails with `EINVAL` on this repository's
development host (`Ubuntu 6.8.0-139-generic`, valid params, page-aligned
ring, power-of-two entries — reproducer `scratch/pbufring.c`). On that kernel
the Owner correctly selects `RawReadiness` and
`ProductionQualification::qualified()` is **false**.

So the managed datapath is implemented and selectable, but the dev host cannot
exercise it. This document records the run that does, on a kernel whose
provided-buffer ring registers, **without rebooting the development host**:
`linux-image-7.0.0-31-generic` was already installed, so it is booted under
QEMU (TCG, `-cpu max` because the workspace builds with
`-C target-cpu=x86-64-v3`).

## What is under test

The production path, not a replica of it:

- `production_runtime_builder(ProductionRuntimeConfig::for_owner(64, 1500))`
  — forced `DriverType::IoUring`, explicit SQ/CQ, `single_issuer`, explicit
  provided-buffer pool, `rx_buffer_len = 2048` (derived from the 1500-byte
  wire ceiling: 256 slots x 2048 B = 512 KiB, not 16 MiB).
- `Owner::new(64)` + `set_rx_mode_policy(RxModePolicy::ManagedRequired)` +
  `Owner::listen(&ListenerConfig)` — the sealed production attach path, which
  under `ManagedRequired` refuses to attach at all without the substrate.
- Traffic: one 64-byte datagram (legal) and one 4096-byte datagram (beyond
  both the 1500-byte wire ceiling and the 2048-byte ring slot).

## Method

```sh
# once: the workspace binary is x86-64-v3, so the guest CPU must implement it
qemu-system-x86_64 -cpu max \
  -kernel vmlinuz-7.0.0-31 -initrd initrd-test.gz \
  -append "console=ttyS0 panic=-1 loglevel=4" \
  -nographic -no-reboot -m 3072 -smp 2
```

The initramfs is `busybox-static` + `ld-linux` + `libc`/`libm`/`libgcc_s` +
one binary, with an `init` that mounts `/proc`, `/sys`, `/dev`, brings up
`lo`, runs the binary, and powers off. Two binaries were run this way:

1. `crates/srt-transport`'s own test binary, filtered to the committed
   regression test;
2. a standalone probe (`scratch/managedrx`, gitignored) that prints the
   runtime profile and ring counters as well.

## Results

### Committed regression test, kernel 7.0.0-31-generic

```text
GUEST_READY kernel=7.0.0-31-generic

running 1 test
test compio_transport::tests::managed_multishot_delivers_and_counts_truncated_datagrams ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 292 filtered out; finished in 0.29s

GUEST_TEST_EXIT=0
```

### Standalone probe, same kernel

```text
GUEST_READY kernel=7.0.0-31-generic
PROFILE sq=512 cq=1024 ring_entries=256 rx_buffer_len=2048
PROFILE iouring=true buffer_pool_ok=true
PROFILE rx_mode=Some(ManagedMultishot) listening_on=127.0.0.1:51209
MANAGEDRX_RESULT pass rx_mode=ManagedMultishot delivered=1 truncated=1 dropped=0 depth=0 capacity=256 ring_entries_ok=true fault=false
MANAGEDRX_SHUTDOWN drained=true in_flight=0 pool_free=64 pool_capacity=64
GUEST_DONE
```

## Leak found and fixed by this run

Running the committed test under ASan+LSan *inside the capable guest* (the
same configuration as the repository's Address-sanitizer CI job) reported:

```text
==88==ERROR: LeakSanitizer: detected memory leaks
Indirect leak of 524288 byte(s) in 256 object(s) allocated from: ...
SUMMARY: AddressSanitizer: 607620 byte(s) leaked in 278 allocation(s).
```

524,288 bytes in 256 objects is exactly the provided-buffer pool
(256 slots x 2048 B). An isolated probe established the ownership boundary:

```text
GUEST_READY kernel=7.0.0-31-generic
PROBE buffer_pool_ok=true
PROBE runtime_dropped
PROBE_EXIT=0
```

i.e. Compio frees its pool correctly when nothing is armed. The leak was ours:
teardown cancelled the managed RX task by dropping its `JoinHandle`, which
cancels without running the unwinding to completion, leaving the armed managed
receive's leases outstanding inside the runtime.

Fix: `shutdown_and_drain` now stops receive intake first
(`SideRx::stop_and_join`) — set `shutdown`, wake, **await** the task
cancellation, drop any staged completion, clear the ring — before it drains TX.
Re-running the same ASan build in the same guest:

```text
GUEST_READY kernel=7.0.0-31-generic
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 346 filtered out; finished in 0.61s
GUEST_MANAGED_EXIT=0
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 346 filtered out; finished in 0.22s
GUEST_FAULT_EXIT=0
```

No leak. This is why the managed-buffer contract is "return to zero after
drain/shutdown": cancelling without awaiting is not enough.

## What this establishes

- **The production Owner selects and requires the managed datapath when the
  kernel can provide it.** `buffer_pool_ok=true` and
  `rx_mode=ManagedMultishot` on a `ManagedRequired` Owner, i.e. the attach path
  that fails closed on an unqualified host succeeds here.
- **A legal datagram is delivered through the managed ring**: `delivered=1`
  for one 64-byte datagram, with the fixed 256-entry ring reporting
  `depth=0` after consumption (the lease is returned, not retained).
- **Truncation is detected, counted, and never parsed**: a 4096-byte datagram
  — larger than both the wire ceiling and the ring slot — produced
  `truncated=1`, `dropped=0`, `fault=false`. No partial datagram reached
  `srt-proto`.
- **Shutdown is quiescent with the managed consumer attached**:
  `drained=true`, `in_flight=0`, `pool_free=64/64`.
- The pooled slot sizing is the wire-ceiling-derived 2048 bytes, not the
  64 KiB UDP maximum.
- The committed test **self-skips** where the substrate is absent (the dev
  host), so it is a durable check that becomes real on any qualified kernel
  rather than a host-pinned assertion.

## What this does not establish

- Not a capacity result. `docs/results/qual-shared-owner-frontier.md` remains
  the capacity evidence, and its rows are raw-reader rows on this host; the
  600/1000 tiers did not establish there for host/sharding reasons.
- Not a claim that this dev host is qualified: on `6.8.0-139-generic` the
  Owner still runs `RawReadiness` and `ProductionQualification::qualified()`
  is false.
- Not a substitute for running the qualification harness on a production
  kernel; it narrows the remaining work to "run the existing harness on a
  kernel whose ring registers", with the datapath itself now verified.
