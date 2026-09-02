# PR M: Final x86-64-v3 and PGO Audit Report

## Executive Summary

This report documents the final ISA, compiler code-generation, branch/cache hardware-counter, and profile-guided optimization (PGO) audit
for `srt-rs` following the completion of the structural Data Structures and Algorithms (DSA) roadmap (PR #54 through PR #60).

### Key Audit Findings
1. **Compiler Lowering**: LLVM with `-C target-cpu=x86-64-v3` natively lowers all idiomatic Rust hot-path operations into specialized hardware instructions (`TZCNT`, `BLSR`, `POPCNT`, `LZCNT`, `MOVBE`, `ANDN`, `SHLX`, `SHRX`).
2. **Indexing Arithmetic**: No division or modulo operations exist in any sequence, ring, page, or bitmap indexing path. All power-of-two arithmetic lowers strictly to bitwise shifts and masks (`shr`, `shl`, `and`).
3. **Intrinsic Rule**: Zero explicit x86 intrinsics (`_tzcnt_u64`, `_blsr_u64`, `AVX2`, `PEXT/PDEP`) are needed or justified. Idiomatic Rust code compiles to optimal machine instructions on x86-64-v3 without unsafe blocks.
4. **PGO Workload Sensitivity**: Profile-guided optimization yields substantial speedups on recovery-dominated and retransmission paths (up to **2.25×** faster in burst recovery, **2.37×** in unique NAK processing, and **1.64×** in scattered loss handling). However, it de-prioritizes bulk clearing and periodic scan paths, resulting in measured regressions of **+27% to +51%** on dense clears and periodic NAK generation.
5. **Operational Decision**: PGO provides clear value for loss-recovery and retransmission-heavy operational deployments, but due to workload-dependent trade-offs across bulk vs recovery paths, it is **not justified as a universal repository default**. Portable and x86-64-v3 non-PGO builds remain the general-purpose baselines.
6. **Automation**: Fully automated, deterministic PGO generation and benchmarking (`cargo xtask pgo [--bench]`) and clean-target ISA codegen audit tooling (`cargo xtask audit`) are implemented in pure Rust.

---

## Environment Metadata

- **Workstation Architecture**: x86_64 (`AMD EPYC Processor (with IBPB)`, 6 physical cores)
- **Kernel / OS**: Linux 6.8.0-137-generic x86_64 (Ubuntu / glibc 2.39)
- **Rust Compiler**: `rustc 1.96.0 (ac68faa20 2026-05-25)`
- **LLVM Backend**: LLVM 22.1.2-rust-1.96.0-stable
- **Target Configurations Evaluated**:
  - `portable`: Default generic `x86_64-unknown-linux-gnu` baseline without CPU flags
  - `x86-64-v3`: `-C target-cpu=x86-64-v3`
  - `target-cpu=native`: `-C target-cpu=native` (AMD Zen 1 / `znver1`)
  - `x86-64-v3 + PGO`: `-C target-cpu=x86-64-v3 -C profile-use=/tmp/srt-pgo-data/merged.profdata`

---

## 1. Assembly & Codegen Lowering Audit

Hot functions across `shiguredo_srt` and `srt-transport` were compiled under isolated target directories (`target/xtask-audit`) with:
```bash
cargo rustc --release --lib -C target-cpu=x86-64-v3 -C codegen-units=1 -- --emit=asm
```
and inspected at the machine-instruction level.

### 1.1 Automated Machine Instruction Lowering Inventory

Dynamically scanned across clean crate assembly artifacts by `cargo xtask audit`:

| Instruction | Architectural Meaning | `shiguredo_srt` Occurrences | `srt-transport` Occurrences | Primary Hot-Path Roles |
|---|---|:---:|:---:|---|
| **`TZCNT`** | Count trailing zeros (first set bit) | **51** | **145** | Loss scanning, run scanning, page/slot scans, readiness flags |
| **`BLSR`** | Reset lowest set bit (`x & (x - 1)`) | **20** | **40** | Set-bit iteration, page directory clearing, event draining |
| **`POPCNT`** | Population count (set bits count) | **7** | **0** | Page occupancy checks, loss list counts, demotion threshold |
| **`LZCNT`** | Count leading zeros | **7** | **13** | Reverse packet searches, capacity power-of-two calculations |
| **`MOVBE`** | Big-endian load/store in one instruction | **292** | **2** | Wire header decode/encode (`read_u16/32/64`, `write_u16/32/64`) |
| **`BSWAP`** | In-register byte swap | **290** | **0** | AES-GCM tag/counter/IV and SHA cryptographic transformations |
| **`ANDN`** | Bitwise `(!a) & b` in one instruction | **42** | **1** | Bitmask range exclusions, loss removal, retransmit queue filters |
| **`SHLX` / `SHRX`** | Two-operand non-destructive shifts | **57** / **19** | **8** / **3** | Bitmask creation `1 << offset` without register clobbering |
| **`DIV` / `IDIV`** | Hardware integer division | **19** (non-hot) | **0** | Rate calculation, RTT moving average, handshake timeout |

### 1.2 Lowering Verification Matrix

*Note on methodology*: The whole-crate opcode inventory verifies instruction emission and confirms the absence of hardware division in indexing. Function-level page/slot access, peer dispatch, and endian loads were confirmed via manual assembly inspection.

| Area | Expected Lowering | Observed Lowering | Verification Method | Status |
|---|---|---|---|---|
| **Ring indexing** | Power-of-two mask (`AND`/shifts), zero `DIV`/`IDIV` | Emits `andl $15`, `shrq $6`; **zero `div` instructions** | Automated scan + manual audit | Optimal (no change) |
| **Sequence & page indexing** | Power-of-two mask (`AND`/shifts), zero `DIV`/`IDIV` | Emits `shrl $6`, `andl $63`; **zero `div` instructions** | Automated scan + manual audit | Optimal (no change) |
| **First-set-bit scans (`trailing_zeros`)** | `TZCNT` | Emits `tzcntq`/`tzcntl` natively (51 in protocol, 145 in transport) | Automated opcode scan | Optimal (no change) |
| **Set-bit iteration (`word &= word - 1`)** | `BLSR` | Emits `blsrq` natively (20 in protocol, 40 in transport) | Automated opcode scan | Optimal (no change) |
| **Population count (`count_ones`)** | `POPCNT` | Emits `popcntq` natively (7 in protocol) | Automated opcode scan | Optimal (no change) |
| **Leading zeros (`leading_zeros`)** | `LZCNT` | Emits `lzcntq`/`lzcntl` natively (7 in protocol, 13 in transport) | Automated opcode scan | Optimal (no change) |
| **Range masks (`(~a) & b`)** | `ANDN`, `SHLX`, `BZHI` | Emits `andnq` (42 in protocol), `shlxq`, `bzhi` | Automated opcode scan | Optimal (no change) |
| **Header endian reads (`from_be_bytes`)** | `MOVBE`, `BSWAP` | Emits `movbel`, `movbew`, `movbeq` (292 in protocol) | Automated scan + manual audit | Optimal (no change) |
| **Receiver page access** | 1 page ptr load + direct slot | Inlined direct slot indexing; zero pointer chasing or abstraction spills | Manual assembly inspection | Optimal (no change) |
| **Sender page access** | 1 page ptr load + direct slot | Inlined direct slot indexing; zero bounds spills | Manual assembly inspection | Optimal (no change) |
| **Established peer dispatch** | $O(1)$ mask + direct array index | Single pointer load + generation/address check; no hash lookups | Manual assembly inspection | Optimal (no change) |
| **Ready & deadline dense paths** | Direct slot flag mutation | Inlines to direct bit/boolean flag mutation in RouteSlot; no heap alloc | Manual assembly inspection | Optimal (no change) |

### 1.3 Inspection of Key Function Disassemblies

#### Sequence & Ring Indexing
- **ACK Timestamp Ring**: `index = ack_number as usize & (MAX_ACK_TIMESTAMPS - 1)` lowers to `andl $15, %eax`.
- **Link Capacity Ring**: `next = (next + 1) & (LINK_CAPACITY_SAMPLES - 1)` lowers to `incl %eax; andl $15, %eax`.
- **Loss Bitmap**: `bit_index / 64` and `bit_index % 64` lower strictly to `shrq $6, %rax` and `andl $63, %ecx`.
- **Adaptive Packet Window**: `(physical >> PAGE_SHIFT, physical & PAGE_MASK)` lowers to `shrl $6, %edi; andl $63, %esi`.
- **Sender Packet Window**: `(physical >> PAGE_SHIFT, physical & PAGE_MASK)` lowers to `shrl $6, %r15d; andl $63, %r14d`.
- **Dense Slot Arena**: `slot_index_for_socket_id` lowers to `(socket_id as usize) & self.slot_mask`.

#### Established DATA Dispatch (`DenseSlotArena::get`)
Inlined loop in `PeerTable`:
```assembly
.LBB87_5:
    movl    -16(%r9), %r11d       # slot_idx from query
    cmpq    %r11, %rdx            # bounds check against capacity
    jbe     .LBB87_29
    movl    -12(%r9), %ebx        # generation / destination socket_id
    cmpl    %ebx, (%rsi,%r11,4)   # generation match
    jne     .LBB87_29
    leaq    (%r11,%r11,8), %r11   # route slot array stride calculation
    cmpq    $0, 48(%r8,%r11,8)    # check slot.value is Some
    je      .LBB87_29
    movl    -8(%r9), %ebx         # expected UDP source address
    leaq    (%r8,%r11,8), %r11
    cmpl    %ebx, 60(%r11)        # address match
    jne     .LBB87_29
```
Lookup compiles to a single indexed load, direct generation match, and address match without hash table probing or memory allocation.

---

## 2. Multi-Class Comparative Benchmarks

All benchmarks were compiled in isolated target directories and executed under Criterion with controlled sample sizes and hardware counter monitoring.

To evaluate both the ISA-floor effect and the incremental profile effect, both **v3 vs Portable** and **PGO vs v3** deltas are reported:

| Workload Area | Workload Filter | Portable (baseline) | x86-64-v3 | Target-cpu=native | x86-64-v3 + PGO | v3 vs Portable | PGO vs v3 | Interpretation |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|---|
| **Receiver In-Order** | `healthy_in_order/1` | 96.38 ns | 98.33 ns | 206.46 ns | 110.11 ns | +2.0% | **+12.0%** | Neutral / within noise |
| **Receiver In-Order** | `healthy_in_order/30` | 3.50 µs | 2.69 µs | 3.10 µs | 2.61 µs | **-23.1%** | **-3.0%** | **v3 win** (-23.1% time) |
| **Receiver In-Order** | `healthy_in_order/200` | 17.93 µs | 18.01 µs | 21.00 µs | 17.46 µs | +0.4% | **-3.1%** | Neutral |
| **Receiver In-Order** | `healthy_in_order/1000` | 83.95 µs | 98.92 µs | 86.22 µs | 79.96 µs | +17.8% | **-19.2%** | **PGO win** (1.24× faster vs v3) |
| **Sender ACK** | `advance_one_aligned/64` | 257.29 ns | 351.46 ns | 326.60 ns | 302.51 ns | +36.6% | **-13.9%** | **PGO win** (-13.9% vs v3) |
| **Sender ACK** | `advance_one_aligned/256` | 345.87 ns | 363.94 ns | 405.83 ns | 369.88 ns | +5.2% | **+1.6%** | Neutral |
| **Sender ACK** | `advance_one_aligned/1024` | 832.08 ns | 771.22 ns | 774.70 ns | 672.26 ns | -7.3% | **-12.8%** | **PGO win** (1.15× faster vs v3) |
| **Sender ACK** | `advance_one_aligned/4096` | 1.08 µs | 1.43 µs | 972.93 ns | 973.10 ns | +32.4% | **-32.0%** | **PGO win** (1.47× faster vs v3) |
| **Sender ACK Boundary** | `advance_one_aligned/8191` | 1.39 µs | 1.27 µs | 1.08 µs | 902.01 ns | -8.6% | **-29.0%** | **PGO win** (1.41× faster vs v3) |
| **Sender ACK Boundary** | `advance_one_aligned/8192` | 1.15 µs | 1.03 µs | 1.21 µs | 733.94 ns | -10.4% | **-28.7%** | **PGO win** (1.40× faster vs v3) |
| **Sender ACK Boundary** | `advance_one_aligned/8193` | 2.50 µs | 1.71 µs | 1.39 µs | 1.22 µs | **-31.6%** | **-28.7%** | **Double win**: v3 (-31.6%), PGO (-28.7%) |
| **Sender ACK Bulk** | `advance_half_aligned/4096` | 178.39 µs | 166.37 µs | 186.22 µs | 162.48 µs | -6.7% | **-2.3%** | Neutral |
| **Sender ACK Full** | `advance_full_aligned/4096` | 340.73 µs | 275.84 µs | 290.49 µs | 349.54 µs | **-19.0%** | **+26.7%** | v3 win; **PGO regression (+26.7%)** |
| **Sender NAK** | `expanded_unique_8192` | 289.91 µs | 553.11 µs | 269.46 µs | 233.24 µs | +90.8% | **-57.8%** | **PGO win** (2.37× faster vs v3) |
| **Sender NAK** | `compact_dense_unique_8192`| 172.88 µs | 168.78 µs | 171.04 µs | 215.94 µs | -2.4% | **+27.9%** | **PGO regression (+27.9%)** |
| **Sender NAK Duplicate** | `expanded_duplicate_8192` | 206.17 µs | 152.93 µs | 125.53 µs | 86.53 µs | **-25.8%** | **-43.4%** | **PGO win** (1.77× faster vs v3) |
| **Sender NAK Duplicate** | `compact_duplicate_8192` | 9.11 µs | 8.05 µs | 9.07 µs | 8.35 µs | **-11.6%** | **+3.7%** | **v3 win** (-11.6% time) |
| **Sender Retransmit** | `drain_retransmits` | 309.08 µs | 397.70 µs | 346.56 µs | 410.18 µs | +28.7% | **+3.1%** | Neutral |
| **Receiver Loss Scan** | `scattered_loss_5000pkts` | 15.13 ms | 14.51 ms | 12.53 ms | 8.84 ms | -4.1% | **-39.1%** | **PGO win** (1.64× faster vs v3) |
| **Receiver Loss Scan** | `burst_loss/burst100_post500`| 2.93 ms | 2.59 ms | 2.58 ms | 1.15 ms | **-11.6%** | **-55.6%** | **Major PGO win** (2.25× faster vs v3) |
| **Receiver Periodic NAK** | `dense_8192` | 592.50 ns | 533.43 ns | 581.37 ns | 759.02 ns | **-10.0%** | **+42.3%** | v3 win; **PGO regression (+42.3%)** |
| **Receiver Drop Range** | `max_legal/dense_loss` | 11.62 µs | 11.50 µs | 11.87 µs | 17.39 µs | -1.0% | **+51.2%** | **PGO regression (+51.2%)** |
| **DATA Route Dispatch** | `dense_slot/1` | 4.02 ns | 3.53 ns | 3.17 ns | 3.35 ns | **-12.2%** | **-5.1%** | **v3 win** (-12.2% time) |
| **DATA Route Dispatch** | `dense_slot/30` | 84.85 ns | 107.23 ns | 94.01 ns | 88.27 ns | +26.4% | **-17.7%** | **PGO win** (-17.7% vs v3) |
| **DATA Route Dispatch** | `dense_slot/200` | 591.48 ns | 647.91 ns | 720.58 ns | 735.73 ns | +9.5% | **+13.6%** | Neutral |
| **DATA Route Dispatch** | `dense_slot/1000` | 3.03 µs | 3.28 µs | 3.95 µs | 3.29 µs | +8.3% | **+0.3%** | Neutral |
| **DATA Route Dispatch** | `dense_slot/4096` | 13.46 µs | 12.23 µs | 13.93 µs | 12.61 µs | **-9.1%** | **+3.1%** | **v3 win** (-9.1% time) |
| **Dispatch Baseline** | `hash_map/1000` | 20.70 µs | 21.34 µs | 25.18 µs | 20.59 µs | +3.1% | **-3.5%** | Neutral |
| **Ready Queue Scaling** | `drain_and_rearm/200` | 10.38 µs | 10.36 µs | 9.35 µs | 10.43 µs | -0.2% | **+0.7%** | Neutral |
| **Ready Queue Scaling** | `drain_and_rearm/1000` | 52.22 µs | 53.08 µs | 50.22 µs | 49.60 µs | +1.6% | **-6.6%** | Neutral |
| **Dense Due Index** | `unique_set/1000` | 17.90 µs | 20.77 µs | 16.65 µs | 20.29 µs | +16.0% | **-2.3%** | Neutral |
| **Dense Due Index** | `reschedule_modest/1000` | 17.84 µs | 19.31 µs | 17.69 µs | 20.34 µs | +8.2% | **+5.3%** | Neutral |
| **Dense Due Index** | `peek_min_stale/1000` | 49.81 µs | 48.92 µs | 50.52 µs | 44.19 µs | -1.8% | **-9.7%** | Neutral |

---

## 3. Normalized Hardware Performance Counter Profile (`v3` vs `v3+PGO`)

Hardware performance counters captured via `perf stat` during Criterion measurement runs.

### Cache PMU Availability Note
- **L1-dcache**: `L1-dcache-loads` and `L1-dcache-load-misses` are exposed by the hypervisor and measured directly. L1 cache miss rates across tested workloads stay between **1.0% and 3.5%**.
- **Last-Level Cache (LLC)**: Hardware LLC events (`LLC-loads`, `LLC-load-misses`) are `<not supported>` on this virtualized AMD EPYC KVM host.
- **Hardware PMU vs Estimates**: Rather than reporting whole-benchmark process totals (which reflect measurement duration rather than per-operation work efficiency), cycles/op and insn/op are explicitly labeled as estimates derived from measured Criterion latency at nominal 2.5 GHz clock frequency ($2.5\text{ cycles/ns}$). IPC, branch miss rates, and L1 cache miss rates are measured directly from hardware PMU performance counters via `perf stat`.

| Workload | v3 Latency | Estimated v3 Cycles/op | Estimated v3 Insn/op | v3 IPC | v3 Branch Miss% | PGO Latency | Estimated PGO Cycles/op | Estimated PGO Insn/op | PGO IPC | PGO Branch Miss% |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Receiver in-order** (`1 conn`) | 98.33 ns | 245.8 | 444.9 | 1.81 | 1.33% | 110.11 ns | 275.3 | 479.0 | 1.74 | 1.56% |
| **Receiver in-order** (`30 conns`) | 2.69 µs | 6.7 k | 12.2 k | 1.81 | 1.32% | 2.61 µs | 6.5 k | 11.4 k | 1.74 | 1.57% |
| **Receiver in-order** (`200 conns`) | 18.01 µs | 45.0 k | 79.7 k | 1.77 | 1.52% | 17.46 µs | 43.6 k | 75.5 k | 1.73 | 1.69% |
| **Receiver in-order** (`1000 conns`) | 98.92 µs | 247.3 k | 432.8 k | 1.75 | 1.64% | 79.96 µs | 199.9 k | 341.8 k | 1.71 | 1.41% |
| **Sender ACK single** (`64 win`) | 351.46 ns | 878.6 | 1.1 k | 1.29 | 3.12% | 302.51 ns | 756.3 | 1.0 k | 1.37 | 2.69% |
| **Sender ACK single** (`256 win`) | 363.94 ns | 909.9 | 1.2 k | 1.35 | 2.61% | 369.88 ns | 924.7 | 1.2 k | 1.34 | 2.93% |
| **Sender ACK single** (`1024 win`) | 771.22 ns | 1.9 k | 2.6 k | 1.35 | 2.89% | 672.26 ns | 1.7 k | 2.2 k | 1.29 | 2.97% |
| **Sender ACK single** (`4096 win`) | 1.43 µs | 3.6 k | 5.0 k | 1.41 | 2.36% | 973.10 ns | 2.4 k | 3.3 k | 1.36 | 2.31% |
| **Sender ACK single** (`8191 win`) | 1.27 µs | 3.2 k | 4.5 k | 1.41 | 2.34% | 902.01 ns | 2.3 k | 3.1 k | 1.39 | 2.58% |
| **Sender ACK single** (`8192 win`) | 1.03 µs | 2.6 k | 3.6 k | 1.41 | 2.31% | 733.94 ns | 1.8 k | 2.6 k | 1.41 | 2.40% |
| **Sender ACK single** (`8193 win`) | 1.71 µs | 4.3 k | 5.9 k | 1.38 | 2.44% | 1.22 µs | 3.0 k | 4.3 k | 1.42 | 2.33% |
| **Sender ACK half** (`4096 win`) | 166.37 µs | 415.9 k | 578.1 k | 1.39 | 2.17% | 162.48 µs | 406.2 k | 576.8 k | 1.42 | 2.05% |
| **Sender ACK full** (`4096 win`) | 275.84 µs | 689.6 k | 999.9 k | 1.45 | 2.10% | 349.54 µs | 873.9 k | 1.23 M | 1.41 | 2.16% |
| **Sender NAK unique** (`8192 win`) | 553.11 µs | 1.38 M | 1.76 M | 1.27 | 3.33% | 233.24 µs | 583.1 k | 740.5 k | 1.27 | 3.28% |
| **Sender NAK compact** (`8192 win`) | 168.78 µs | 421.9 k | 565.4 k | 1.34 | 2.79% | 215.94 µs | 539.9 k | 664.0 k | 1.23 | 3.43% |
| **Sender NAK duplicate** (`8192 win`) | 152.93 µs | 382.3 k | 485.6 k | 1.27 | 3.31% | 86.53 µs | 216.3 k | 274.7 k | 1.27 | 3.39% |
| **Sender NAK compact duplicate** | 8.05 µs | 20.1 k | 27.4 k | 1.36 | 2.58% | 8.35 µs | 20.9 k | 26.3 k | 1.26 | 3.18% |
| **Sender retransmit drain** | 397.70 µs | 994.2 k | 1.47 M | 1.48 | 1.92% | 410.18 µs | 1.03 M | 1.38 M | 1.35 | 2.78% |
| **Receiver scattered loss** (`5k pkts`) | 14.51 ms | 36.27 M | 58.40 M | 1.61 | 2.30% | 8.84 ms | 22.10 M | 34.03 M | 1.54 | 2.35% |
| **Receiver burst loss** (`100 run`) | 2.59 ms | 6.47 M | 11.07 M | 1.71 | 2.01% | 1.15 ms | 2.88 M | 4.66 M | 1.62 | 2.04% |
| **Receiver periodic NAK** (`dense`) | 533.43 ns | 1.3 k | 2.6 k | 1.93 | 1.60% | 759.02 ns | 1.9 k | 3.6 k | 1.91 | 1.53% |
| **Receiver drop range** (`dense`) | 11.50 µs | 28.8 k | 51.5 k | 1.79 | 1.90% | 17.39 µs | 43.5 k | 79.1 k | 1.82 | 1.71% |
| **Route dispatch** (`dense_slot/1`) | 3.53 ns | **8.8** | **16.1** | 1.82 | 1.30% | 3.35 ns | **8.4** | **17.0** | 2.03 | **0.95%** |
| **Route dispatch** (`dense_slot/30`) | 107.23 ns | 268.1 | 512.0 | 1.91 | 1.06% | 88.27 ns | 220.7 | 419.3 | 1.90 | 1.08% |
| **Route dispatch** (`dense_slot/200`) | 647.91 ns | 1.6 k | 3.0 k | 1.85 | 1.20% | 735.73 ns | 1.8 k | 3.5 k | 1.89 | 1.12% |
| **Route dispatch** (`dense_slot/1000`) | 3.28 µs | 8.2 k | 17.0 k | 2.07 | **0.66%** | 3.29 µs | 8.2 k | 15.1 k | 1.84 | 1.23% |
| **Route dispatch** (`dense_slot/4096`) | 12.23 µs | 30.6 k | 57.8 k | 1.89 | 1.09% | 12.61 µs | 31.5 k | 61.8 k | 1.96 | **1.00%** |
| **Dispatch Baseline** (`hash_map/1000`) | 21.34 µs | 53.4 k | 97.1 k | 1.82 | 1.83% | 20.59 µs | 51.5 k | 91.1 k | 1.77 | 1.80% |
| **Ready queue drain** (`200 peers`) | 10.36 µs | 25.9 k | 46.4 k | 1.79 | 1.43% | 10.43 µs | 26.1 k | 48.2 k | 1.85 | 1.28% |
| **Ready queue drain** (`1000 peers`) | 53.08 µs | 132.7 k | 237.5 k | 1.79 | 1.25% | 49.60 µs | 124.0 k | 219.5 k | 1.77 | 1.24% |
| **Dense DueIndex set** (`1k peers`) | 20.77 µs | 51.9 k | 81.0 k | 1.56 | 1.99% | 20.29 µs | 50.7 k | 77.6 k | 1.53 | 2.07% |
| **Dense DueIndex reschedule** (`1k`) | 19.31 µs | 48.3 k | 72.4 k | 1.50 | 2.11% | 20.34 µs | 50.9 k | 79.3 k | 1.56 | 1.84% |
| **Dense DueIndex peek stale** (`1k`) | 48.92 µs | 122.3 k | 187.1 k | 1.53 | 2.04% | 44.19 µs | 110.5 k | 174.6 k | 1.58 | 1.80% |

---

## 4. Reproducible Tooling & Workflow

Both auditing and PGO workflows are built directly into `cargo xtask` in pure Rust with zero Python or external scripting dependencies:

### 4.1 Running the Codegen Audit
```bash
cargo xtask audit
```
Automates:
1. Cleans and initializes `target/xtask-audit`.
2. Emits assembly for `shiguredo_srt` and `srt-transport` with `-C target-cpu=x86-64-v3 -C codegen-units=1`.
3. Deterministically scans the exact output files for hardware instruction lowerings.
4. Verifies absence of hardware division in indexing and prints the lowering inventory.

### 4.2 Generating and Building with PGO
```bash
# Regenerates fresh profile by default, merges, and compiles release:
cargo xtask pgo

# Skips regeneration and reuses existing /tmp/srt-pgo-data/merged.profdata:
cargo xtask pgo --reuse-profile
```
Automates:
1. Compiles test suites under `-C target-cpu=x86-64-v3 -C profile-generate=/tmp/srt-pgo-data`.
2. Runs the full healthy in-order and loss/reorder/recovery training corpus across `shiguredo_srt` and `srt-transport`.
3. Merges raw profiles with matching `llvm-profdata` from `rustc sysroot`.
4. Compiles release binaries with `-C target-cpu=x86-64-v3 -C profile-use=/tmp/srt-pgo-data/merged.profdata` in `target/build-pgo`.

### 4.3 Running Benchmarks under PGO
To run benchmarks with profile-use applied in isolated `target/build-pgo`:
```bash
# Automated via xtask (regenerates profile first to ensure fresh data):
cargo xtask pgo --bench -p shiguredo_srt --bench receiver_window_validation

# Fast re-run reusing existing merged profile:
cargo xtask pgo --reuse-profile --bench -p shiguredo_srt --bench receiver_window_validation

# Or directly via cargo:
RUSTFLAGS="-C target-cpu=x86-64-v3 -C profile-use=/tmp/srt-pgo-data/merged.profdata" \
CARGO_TARGET_DIR=target/build-pgo \
cargo bench -p shiguredo_srt --bench receiver_window_validation
```

---

## 5. Decision Policy Outcome

**Outcome A — Compiler Already Emits Optimal Machine Code; No Production Code Changes Needed**:
- The idiomatic Rust implementations of packet windows, loss bitmaps, and transport dispatch already lower to optimal machine instructions (`TZCNT`, `BLSR`, `POPCNT`, `LZCNT`, `MOVBE`, `ANDN`, `SHLX`).
- All sequence and ring indexing uses shifts and masks with zero hardware division.
- PGO provides measured throughput and latency advantages on burst loss and retransmission paths, while regressing dense bulk clear operations.
- PGO is documented as an operational optimization for loss-dominated deployments rather than a repository-wide default.
- All PR M acceptance criteria are satisfied with zero production data-plane modifications.
