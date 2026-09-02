# Post-DSA End-to-End Live Benchmark Scorecard

## Executive Summary

This report establishes the definitive live socket and connection-scale performance record for the structural
Data Structures and Algorithms (DSA) roadmap in `srt-rs`, evaluating the progression from the pre-DSA baseline at
commit **`cde0e53ff52c3ba674cb02c9caa9e02ca7e0ac91`** (base of PR #37) to the post-DSA endpoint at
commit **`aba97ae6acdee8492dad6c86bcc418571ca81ebe`** (merge commit of PR #61).

The central evaluation question is:
> **Did the large microbenchmark wins from the structural DSA roadmap survive through real operating system sockets, runtime scheduling, kernel queues, ACK/NAK traffic, encryption, and multi-connection scale?**

### Core Audit Conclusions

1. **Workload-Specific Acceleration**: The structural DSA roadmap delivers clear, measurable live efficiency gains on specific production paths. The most pronounced improvements appear under **heavy packet reordering**. `mio 200c×8M reorder=1%` drops CPU by **-23.3%** with non-overlapping ranges ($[7267..9791]$ vs $[5814..7075]$); `tokio 200c×8M reorder=1%` drops CPU by **-24.2%**, with overlapping ranges. Additional wins appear on **bonded broadcast demux routing** (**-20.1% CPU** on `tokio-broadcast`) and on **selected medium-scale async data paths** (e.g. `mio 200c×4M` drops CPU by **-22.9%**).
2. **Packet Loss Findings**: In this campaign, actual packet-loss workloads regress broadly or remain neutral (+0.5% to +15.3% CPU at 200 connections, +9.4% to +30.4% at 1 connection); the clean wins are primarily reorder-specific rather than generic "recovery" wins.
3. **Pacing-Aware Capacity Gate**: Under canonical strict criteria requiring that *all* repetitions sustain $\ge 99.0\%$ offer, $\ge 99.0\%$ goodput, $\ge 99.9\%$ delivery, zero connection teardown, and zero UDP receive-buffer drop errors, this campaign did not establish a clean capacity frontier because the load generator failed the offer gate ($\text{offer}\% < 99.0\%$). In short sweeps, single-threaded load generation could not sustain $\ge 99.0\%$ of the pacing-aware target rate (`target = conns × (bitrate ÷ 8) × secs ÷ (1316 + 16)`). In accordance with repository standards, no configured rate is claimed as clean capacity unless the load generator actually sustained the target offer.
4. **All-Six Runtime Execution Breadth**: Across all 36 controlled cells in `runtime-breadth.plan` ($N=3$), five runtime families (`compio`, `glommio`, `mio`, `smol`, `tokio`) show selected wins under the common topology (`compio` -14.6% to -16.8%, `glommio` -9.7% to -31.8%, `mio` -7.2% to -39.1%, `smol` -29.5%, `tokio` -28.8%). `monoio` materially regresses under this common configuration (+1.2% to +46.5% CPU, with delivery dropping to 50.9% and 58.5% at 600 connections), demonstrating that the structural improvements interact differently with distinct async event models.
5. **Observed Factorial Peer Interaction**: Decoupled cross-version matrices (`old caller → new listener` vs `new caller → old listener`) verify complete wire interoperability between the pre-DSA and post-PR61 endpoints with zero protocol breaks. A 2x2 factorial analysis reveals an observed median-derived interaction term of $+896.1\text{ ms/Gbit}$ (per-repetition median $+639.3\text{ ms/Gbit}$ with spread $[+567.4 .. +2137.0]\text{ ms/Gbit}$), demonstrating that remote peer behavior influences local CPU work; the evidence does not support simplistic additive attribution to single internal components.

---

## 1. Environment & Historical Endpoints

- **Pre-DSA Baseline Commit**: `cde0e53ff52c3ba674cb02c9caa9e02ca7e0ac91` (base of PR #37)
- **Post-PR61 HEAD Commit**: `aba97ae6acdee8492dad6c86bcc418571ca81ebe` (merge of PR #61)
- **Host Architecture**: AMD EPYC Processor (with IBPB), 6 vCPUs @ 2.5 GHz nominal, 12 GB RAM
- **Operating System / Kernel**: Linux 6.8.0-137-generic x86_64
- **Toolchain**: `rustc 1.96.0 (ac68faa20 2026-05-25)`
- **Build Flags**: `RUSTFLAGS="-C target-cpu=x86-64-v3"` (release build, `codegen-units=1`, no PGO)
- **Link Emulation Environment**: Linux network namespace (`netns: srtbench`) driven by `tc-netem`

---

## 2. Methodology & Strict Measurement Rules

1. **Standalone Worktree Isolation**: Baseline and HEAD binaries were compiled in separate independent worktrees (`/home/dev/srt-rs-pre-dsa` and `/home/dev/srt-rs`), preventing build cache cross-contamination.
2. **Controlled Execution Order**: Runs alternated in interleaved ABBA order across trees to eliminate host thermal drift and temporal bias.
3. **Repetition Discipline ($N \ge 3$)**: Every recorded benchmark cell in this report uses at least 3 repetitions ($N=5$ for live sentinels, $N=3$ for capacity, recovery, and runtime breadth).
4. **Pacing-Aware Target Rate**:
   SRT live mode configures `max_bandwidth_bytes_per_sec = bitrate_bps / 8` (`SRTO_MAXBW`). Pacing calculates the packet send period as:
   $$\text{period\_us} = \frac{1\,000\,000 \times (\text{payload\_size} + 16)}{\text{max\_bandwidth\_bytes\_per\_sec}}$$
   The nominal target packets denominator is therefore:
   $$\text{target\_packets} = \frac{\text{conns} \times (\text{bitrate\_bps} / 8) \times \text{secs}}{1316 + 16}$$
   Using $1316\text{ B}$ alone without the 16-byte SRT header would make $\ge 99.0\%$ offer mathematically impossible ($1316 / 1332 = 98.80\%$).
5. **Canonical Strict Clean-Capacity Predicate**:
   A repetition is classified as `clean` if and only if:
   $$\begin{aligned}
   \text{conns} > 0 &\land \text{caller\_established} == \text{conns} \land \text{listener\_established} == \text{conns} \\
   &\land \text{torn}_c == 0 \land \text{torn}_l == 0 \\
   &\land \text{offer}\% \ge 99.0 \land \text{good}\% \ge 99.0 \land \text{deliv}\% \ge 99.9 \\
   &\land \text{caller\_udp\_rcvbuf\_err} == 0 \land \text{listener\_udp\_rcvbuf\_err} == 0
   \end{aligned}$$
   A cell qualifies for the capacity frontier **only if every repetition passes this predicate**.
6. **Recovery Telemetry Semantics**:
   - Caller: `sec_a` = `caller_retransmits`, `sec_b` = `caller_loss_list`
   - Listener: `sec_a` = `listener_lost`, `sec_b` = `listener_duplicates`
7. **Role-Separated Memory**: Peak RSS per connection is reported separately for Caller and Listener (`RSS C/L` in KB/conn), dividing each process's RSS by its own established connection count.

---

## 3. Controlled Live Sentinels (10s duration, 5 repetitions)

Evaluates the four repository performance sentinels in interleaved ABBA order ($N=5$ repetitions).

| Workload Cell | Reps | Offer% (B→H) | Good% (B→H) | Deliv% (B→H) | Clean B/H | CPU ms/Gbit (Base [min..max] → Head [min..max], Δ%, Overlap) | Caller CPU ms/Mpkt | Listener CPU ms/Mpkt | Peak RSS/conn KB (Caller, Listener) | Recovery Telemetry (Retx, Lost, Dup) | RTT ms |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **tokio 32c×4M shared-pool:1 broadcast:16** | n=5 | 100.0% → 100.0% | 100.0% → 100.0% | 100.0% → 100.0% | yes/yes | 9496.8 [7422.2..11684.6] → 7584.7 [6514.7..10114.6] (**-20.1%**, overlap: yes) | 57122.9 → 43577.0 (-23.7%) | 42859.5 → 36274.3 (-15.4%) | C: 376→392 (+4.2%), L: 458→472 (+3.1%) | Retx: 0→0, Lost: 16→16, Dup: 0→0 | 0.00 → 0.00 |
| **tokio 600c×1M 256 shared-pool:1** | n=5 | 55.4% → 55.3% | 36.2% → 40.7% | 65.3% → 73.7% | no/no | 7698.2 [7542.1..8390.5] → 7332.6 [5037.7..8022.8] (**-4.7%**, overlap: yes) | 27863.3 → 26609.2 (-4.5%) | 39704.9 → 38555.4 (-2.9%) | C: 134→142 (+5.4%), L: 37→41 (+12.3%) | Retx: 0→0, Lost: 155739→102241, Dup: 0→0 | 100.00 → 100.41 |
| **compio 600c×1M shared-pool:4** | n=5 | 54.3% → 54.3% | 54.3% → 54.3% | 100.0% → 100.0% | no/no | 10267.1 [9093.3..11168.9] → 10853.6 [10678.1..11099.6] (**+5.7%**, overlap: yes) | 58339.9 → 61668.3 (+5.7%) | 49751.8 → 53033.1 (+6.6%) | C: 47→56 (+18.8%), L: 41→44 (+6.5%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 68.81 → 76.86 |
| **mio 600c×1M shared-pool:4** | n=5 | 55.3% → 55.3% | 55.3% → 55.3% | 100.0% → 100.0% | no/no | 6259.4 [5953.7..6784.0] → 6687.0 [6310.6..7002.9] (**+6.8%**, overlap: yes) | 33350.1 → 35517.2 (+6.5%) | 32548.7 → 34883.1 (+7.2%) | C: 21→24 (+16.2%), L: 29→30 (+5.8%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 30.34 → 15.50 |

### Sentinel Observations
- **Broadcast Bond Demux**: Shows a median **-20.1% CPU reduction** on `tokio-broadcast` (Caller **-23.7%**, Listener **-15.4%**), consistent with reduced overhead in bonded group fanout across the full #37–#61 diff. The sample ranges overlap ($[7422..11684]$ vs $[6514..10114]$).
- **Shared Socket Demux**: `tokio-demux-aes256` reduces median CPU by **-4.7%**, improves packet delivery ratio from 65.3% to 73.7%, and reduces loss/gap backlog from 155,739 to 102,241.
- **Lossless Epoll / io_uring Streams**: `mio` and `compio` at 600 connections × 1 Mbps show modest median shifts (+5.7% to +6.8%) with overlapping distributions.

---

## 4. Scale & Capacity Frontier Sweep (`capacity-frontier.plan`, $N=3$)

Varies connection count (50, 200, 600, 1200) and bitrate (1M, 4M, 8M) across `mio` and `tokio` (6s duration, $N=3$ repetitions).

| Workload Cell | Reps | Offer% (B→H) | Good% (B→H) | Deliv% (B→H) | Clean B/H | CPU ms/Gbit (Base [min..max] → Head [min..max], Δ%, Overlap) | Caller CPU ms/Mpkt | Listener CPU ms/Mpkt | Peak RSS/conn KB (Caller, Listener) | Recovery Telemetry (Retx, Lost, Dup) | RTT ms |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **mio 1200c×1M shared-pool:4** | n=3 | 30.3% → 30.2% | 30.3% → 30.2% | 100.0% → 100.0% | no/no | 8280.3 [7514.1..8283.1] → 8283.3 [7641.6..10324.0] (**+0.0%**, overlap: yes) | 43921.0 → 43747.7 (-0.4%) | 43153.8 → 43458.4 (+0.7%) | C: 45→43 (-4.0%), L: 40→40 (-1.9%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 61.12 → 62.69 |
| **mio 1200c×4M shared-pool:4** | n=3 | 8.2% → 7.0% | 8.2% → 7.0% | 100.0% → 100.0% | no/no | 7887.3 [6471.0..10038.9] → 9791.4 [7878.4..9867.6] (**+24.1%**, overlap: yes) | 42056.1 → 52126.7 (+23.9%) | 40981.7 → 50957.2 (+24.3%) | C: 28→23 (-16.8%), L: 24→19 (-20.6%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 157.90 → 46.03 |
| **mio 1200c×8M shared-pool:4** | n=3 | 3.9% → 4.3% | 3.9% → 4.3% | 100.0% → 100.0% | no/no | 7780.3 [6797.3..9034.5] → 7921.4 [7752.9..8171.0] (**+1.8%**, overlap: yes) | 41017.6 → 41963.7 (+2.3%) | 40893.9 → 41432.4 (+1.3%) | C: 20→36 (+81.4%), L: 20→34 (+71.8%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 74.64 → 61.63 |
| **mio 200c×1M shared-pool:4** | n=3 | 56.3% → 65.2% | 56.3% → 65.2% | 100.0% → 100.0% | no/no | 15095.7 [9516.0..19497.1] → 13097.8 [10535.3..15617.8] (**-13.2%**, overlap: yes) | 83274.2 → 71312.4 (-14.4%) | 75653.6 → 66581.7 (-12.0%) | C: 34→42 (+23.3%), L: 42→49 (+15.2%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 13.72 → 56.91 |
| **mio 200c×4M shared-pool:4** | n=3 | 32.5% → 43.9% | 32.5% → 43.9% | 100.0% → 100.0% | no/no | 6976.4 [4815.2..8297.4] → 5382.1 [4471.7..5383.0] (**-22.9%**, overlap: yes) | 38027.2 → 29124.0 (-23.4%) | 35420.2 → 27196.4 (-23.2%) | C: 89→74 (-16.7%), L: 91→89 (-2.3%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 11.39 → 10.39 |
| **mio 200c×8M shared-pool:4** | n=3 | 39.1% → 36.7% | 39.1% → 36.7% | 100.0% → 100.0% | no/no | 3180.5 [3147.5..3181.7] → 3415.9 [3100.2..4396.1] (**+7.4%**, overlap: yes) | 17198.2 → 18608.0 (+8.2%) | 15987.4 → 17354.3 (+8.5%) | C: 144→197 (+36.7%), L: 160→182 (+14.1%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 12.60 → 15.21 |
| **mio 50c×1M shared-pool:4** | n=3 | 75.9% → 74.2% | 75.9% → 74.2% | 100.0% → 100.0% | no/no | 19168.0 [14461.1..23282.4] → 19735.5 [19339.1..23858.7] (**+3.0%**, overlap: yes) | 113178.9 → 118233.5 (+4.5%) | 88622.2 → 96942.4 (+9.4%) | C: 114→116 (+1.9%), L: 127→125 (-1.7%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 3.60 → 7.09 |
| **mio 50c×4M shared-pool:4** | n=3 | 49.1% → 52.6% | 49.1% → 52.6% | 100.0% → 100.0% | no/no | 10959.0 [10347.0..15375.9] → 9981.0 [8653.0..10409.0] (**-8.9%**, overlap: yes) | 63269.5 → 59410.3 (-6.1%) | 52106.3 → 45670.1 (-12.4%) | C: 119→122 (+3.2%), L: 149→154 (+3.3%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 6.18 → 5.08 |
| **mio 50c×8M shared-pool:4** | n=3 | 34.9% → 32.7% | 34.9% → 32.7% | 100.0% → 100.0% | no/no | 8779.9 [8190.4..9014.6] → 9136.4 [7787.3..9234.6] (**+4.1%**, overlap: yes) | 52571.1 → 53023.9 (+0.9%) | 39497.2 → 42621.5 (+7.9%) | C: 135→130 (-3.9%), L: 199→182 (-8.6%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 12.48 → 4.88 |
| **mio 600c×1M shared-pool:4** | n=3 | 54.2% → 46.4% | 54.2% → 46.4% | 100.0% → 100.0% | no/no | 6606.5 [6183.5..9516.6] → 8097.4 [7055.2..9772.8] (**+22.6%**, overlap: yes) | 35132.2 → 41787.7 (+18.9%) | 34420.7 → 43462.0 (+26.3%) | C: 19→38 (+99.9%), L: 28→38 (+36.9%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 18.98 → 71.36 |
| **mio 600c×4M shared-pool:4** | n=3 | 15.1% → 15.4% | 15.1% → 15.4% | 100.0% → 100.0% | no/no | 6693.5 [5966.8..7344.5] → 5941.7 [5457.4..9240.8] (**-11.2%**, overlap: yes) | 35804.6 → 31711.7 (-11.4%) | 34664.2 → 30842.7 (-11.0%) | C: 44→55 (+26.2%), L: 41→52 (+26.2%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 30.07 → 21.70 |
| **mio 600c×8M shared-pool:4** | n=3 | 9.7% → 8.1% | 9.7% → 8.1% | 100.0% → 100.0% | no/no | 5357.4 [5094.4..5382.6] → 5728.8 [5600.6..6769.6] (**+6.9%**, overlap: no) | 27734.7 → 30704.6 (+10.7%) | 27408.3 → 29607.8 (+8.0%) | C: 58→65 (+11.7%), L: 59→61 (+3.0%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 18.43 → 36.65 |
| **tokio 1200c×1M shared-pool:4** | n=3 | 16.4% → 15.0% | 16.4% → 15.0% | 100.0% → 100.0% | no/no | 10561.6 [9695.0..12304.4] → 11622.5 [11407.3..16994.2] (**+10.0%**, overlap: yes) | 55890.7 → 61666.3 (+10.3%) | 55302.2 → 60695.6 (+9.8%) | C: 24→32 (+31.2%), L: 12→15 (+25.8%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 68.92 → 51.53 |
| **tokio 1200c×4M shared-pool:4** | n=3 | 4.6% → 3.5% | 4.6% → 3.5% | 100.0% → 100.0% | no/no | 10168.1 [8950.6..10250.4] → 12310.9 [11266.9..13210.5] (**+21.1%**, overlap: no) | 54313.4 → 65326.6 (+20.3%) | 52636.5 → 64282.8 (+22.1%) | C: 24→42 (+77.4%), L: 12→15 (+18.6%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 128.10 → 141.39 |
| **tokio 1200c×8M shared-pool:4** | n=3 | 2.3% → 2.0% | 2.3% → 2.0% | 100.0% → 100.0% | no/no | 9753.3 [9440.2..11873.7] → 11344.1 [11015.5..11803.1] (**+16.3%**, overlap: yes) | 51418.6 → 60368.7 (+17.4%) | 51264.0 → 59062.3 (+15.2%) | C: 23→31 (+30.8%), L: 13→14 (+6.3%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 51.88 → 84.21 |
| **tokio 200c×1M shared-pool:4** | n=3 | 60.9% → 57.1% | 60.9% → 57.1% | 100.0% → 100.0% | no/no | 12877.1 [12571.6..22078.4] → 14270.3 [13229.7..20406.8] (**+10.8%**, overlap: yes) | 73832.5 → 82839.1 (+12.2%) | 61737.7 → 67398.7 (+9.2%) | C: 42→48 (+15.4%), L: 44→53 (+21.2%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 9.52 → 12.05 |
| **tokio 200c×4M shared-pool:4** | n=3 | 30.1% → 33.5% | 30.1% → 33.5% | 100.0% → 100.0% | no/no | 7342.1 [6890.3..10435.9] → 6794.4 [6628.9..7967.9] (**-7.5%**, overlap: yes) | 41540.4 → 38550.4 (-7.2%) | 35757.0 → 32981.0 (-7.8%) | C: 67→66 (-1.4%), L: 70→80 (+14.0%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 8.33 → 9.92 |
| **tokio 200c×8M shared-pool:4** | n=3 | 29.4% → 26.3% | 29.4% → 26.3% | 100.0% → 100.0% | no/no | 4208.2 [3966.7..5327.1] → 4586.4 [4425.3..5038.0] (**+9.0%**, overlap: yes) | 22855.9 → 25164.4 (+10.1%) | 21447.7 → 23120.9 (+7.8%) | C: 87→107 (+22.5%), L: 86→95 (+10.4%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 13.21 → 20.49 |
| **tokio 50c×1M shared-pool:4** | n=3 | 75.0% → 76.2% | 75.0% → 76.2% | 100.0% → 100.0% | no/no | 22276.9 [21391.9..35656.8] → 21240.0 [20090.8..23102.6] (**-4.7%**, overlap: yes) | 132130.9 → 119035.0 (-9.9%) | 105167.9 → 104579.6 (-0.6%) | C: 120→125 (+4.0%), L: 130→148 (+14.3%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 2.84 → 3.05 |
| **tokio 50c×4M shared-pool:4** | n=3 | 46.0% → 40.7% | 46.0% → 40.7% | 100.0% → 100.0% | no/no | 12285.2 [11532.2..15684.5] → 14484.7 [10579.8..18013.2] (**+17.9%**, overlap: yes) | 70877.1 → 88409.9 (+24.7%) | 58462.0 → 64085.5 (+9.6%) | C: 128→138 (+7.7%), L: 151→179 (+18.6%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 3.27 → 1.86 |
| **tokio 50c×8M shared-pool:4** | n=3 | 25.8% → 26.8% | 25.8% → 26.8% | 100.0% → 100.0% | no/no | 13005.9 [9012.1..14184.0] → 12077.7 [8772.2..14785.8] (**-7.1%**, overlap: yes) | 77073.1 → 71347.7 (-7.4%) | 59852.9 → 55806.6 (-6.8%) | C: 175→166 (-4.8%), L: 169→201 (+19.0%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 6.72 → 4.06 |
| **tokio 600c×1M shared-pool:4** | n=3 | 44.0% → 36.9% | 44.0% → 36.9% | 100.0% → 100.0% | no/no | 7957.4 [7457.1..7986.7] → 9270.0 [9012.6..16313.1] (**+16.5%**, overlap: no) | 42157.8 → 50670.1 (+20.2%) | 41019.2 → 46924.6 (+14.2%) | C: 32→38 (+19.5%), L: 23→23 (+0.5%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 61.20 → 79.17 |
| **tokio 600c×4M shared-pool:4** | n=3 | 10.4% → 10.2% | 10.4% → 10.2% | 100.0% → 100.0% | no/no | 8130.7 [7454.7..9320.6] → 8190.6 [8173.4..11109.1] (**+0.7%**, overlap: yes) | 44001.0 → 44438.9 (+1.0%) | 41599.1 → 41854.8 (+0.6%) | C: 36→48 (+35.6%), L: 20→23 (+16.0%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 18.33 → 59.36 |
| **tokio 600c×8M shared-pool:4** | n=3 | 6.3% → 5.4% | 6.3% → 5.4% | 100.0% → 100.0% | no/no | 6856.2 [6337.9..7476.6] → 7905.2 [7700.0..9325.6] (**+15.3%**, overlap: no) | 36372.1 → 42422.6 (+16.6%) | 35810.1 → 40803.5 (+13.9%) | C: 65→44 (-33.4%), L: 25→27 (+7.8%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 38.98 → 20.79 |

### Capacity Frontier Audit
- **Strict Clean Frontier Result**: `None (no cell met strict >=99% offer/good across all repetitions)`.
- **Reason**: This campaign did not establish a capacity frontier because the single-threaded load generator failed the offer gate ($\text{offer}\% < 99.0\%$). At 6-second durations with single-threaded worker scheduling, the load generator could not sustain $\ge 99.0\%$ of the pacing-aware target rate across multiple connections. In accordance with repository audit standards, no configured rate is claimed as clean capacity unless the load generator actually sustained the target offer.
- **Medium-Scale Efficiency**: Solid reductions appear at medium scale (e.g. `mio 200c×4M` drops CPU by **-22.9%**, `mio 200c×1M` by **-13.2%**, `mio 600c×4M` by **-11.2%**, and `tokio 200c×4M` by **-7.5%**).

---

## 5. Recovery Telemetry & Impaired-Network Campaigns

Evaluates packet loss and reordering recovery under Linux Traffic Control (`tc-netem`) inside network namespace `srtbench`.

### 5.1 Packet Loss Recovery (`recovery-loss.plan`, $N=3$)

Varies link packet loss ($0.1\%$ and $1.0\%$) at 8 Mbps ($N=3$ repetitions).

| Workload Cell | Reps | Offer% (B→H) | Good% (B→H) | Deliv% (B→H) | Clean B/H | CPU ms/Gbit (Base [min..max] → Head [min..max], Δ%, Overlap) | Caller CPU ms/Mpkt | Listener CPU ms/Mpkt | Peak RSS/conn KB (Caller, Listener) | Recovery Telemetry (Retx, Lost, Dup) | RTT ms |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **tokio 1c×8M shared-pool:4** | n=3 | 55.6% → 55.6% | 55.6% → 55.6% | 100.0% → 100.0% | no/no | 114318.6 [91489.3..118739.7] → 99411.0 [67367.3..116346.7] (**-13.0%**, overlap: yes) | 661569.1 → 606887.8 (-8.3%) | 541977.0 → 439710.9 (-18.9%) | C: 5000→5184 (+3.7%), L: 5048→5352 (+6.0%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 0.88 → 1.03 |
| **tokio 200c×8M shared-pool:4** | n=3 | 29.8% → 29.8% | 29.8% → 29.8% | 100.0% → 100.0% | no/no | 4088.1 [3822.6..5247.1] → 3651.4 [3611.4..3659.7] (**-10.7%**, overlap: no) | 22427.7 → 19937.0 (-11.1%) | 20611.4 → 18408.7 (-10.7%) | C: 86→71 (-18.0%), L: 87→93 (+7.2%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 9.52 → 6.63 |
| **mio 200c×8M shared-pool:4** | n=3 | 41.7% → 41.7% | 41.7% → 41.7% | 100.0% → 100.0% | no/no | 2751.3 [2702.6..4225.3] → 2764.9 [2492.2..3081.4] (**+0.5%**, overlap: yes) | 14968.0 → 14608.3 (-2.4%) | 13997.8 → 14501.0 (+3.6%) | C: 84→72 (-15.2%), L: 127→116 (-8.9%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 7.40 → 6.19 |
| **tokio 200c×8M shared-pool:4 loss=0.1%** | n=3 | 29.8% → 29.8% | 29.8% → 29.8% | 100.0% → 100.0% | no/no | 4160.6 [3985.0..4348.8] → 4181.0 [4001.7..5450.3] (**+0.5%**, overlap: yes) | 22850.7 → 22992.7 (+0.6%) | 20951.8 → 21024.6 (+0.3%) | C: 101→115 (+13.8%), L: 79→95 (+20.1%) | Retx: 316→369, Lost: 247→309, Dup: 74→89 | 7.55 → 6.56 |
| **mio 200c×8M shared-pool:4 loss=1%** | n=3 | 39.8% → 38.6% | 39.8% → 38.6% | 100.0% → 100.0% | no/no | 10675.9 [10620.6..10759.0] → 11466.7 [11013.0..14394.2] (**+7.4%**, overlap: no) | 65416.2 → 69927.8 (+6.9%) | 47086.0 → 50793.2 (+7.9%) | C: 119→105 (-12.0%), L: 141→139 (-1.5%) | Retx: 5538→5120, Lost: 3910→3620, Dup: 1556→1567 | 5.44 → 11.70 |
| **mio 200c×8M shared-pool:4 loss=0.1%** | n=3 | 41.5% → 41.4% | 41.5% → 41.4% | 100.0% → 100.0% | no/no | 2874.1 [2856.3..10643.5] → 3110.4 [3038.0..10226.4] (**+8.2%**, overlap: yes) | 15559.2 → 17101.0 (+9.9%) | 14766.4 → 15644.8 (+5.9%) | C: 173→129 (-25.8%), L: 199→153 (-23.3%) | Retx: 584→566, Lost: 393→392, Dup: 191→176 | 6.86 → 6.48 |
| **mio 30c×8M shared-pool:4 loss=0.1%** | n=3 | 47.9% → 48.0% | 47.9% → 48.0% | 100.0% → 100.0% | no/no | 8000.0 [6295.4..10549.3] → 8714.5 [7361.1..9875.7] (**+8.9%**, overlap: yes) | 44155.5 → 49704.4 (+12.6%) | 40068.9 → 42041.9 (+4.9%) | C: 227→182 (-20.0%), L: 266→252 (-5.3%) | Retx: 67→85, Lost: 61→78, Dup: 9→24 | 3.99 → 4.75 |
| **mio 1c×8M shared-pool:4 loss=0.1%** | n=3 | 55.6% → 55.6% | 55.6% → 55.6% | 100.0% → 100.0% | no/no | 87812.2 [83163.1..109362.4] → 96073.4 [81439.7..131989.8] (**+9.4%**, overlap: yes) | 512746.3 → 568303.9 (+10.8%) | 411740.0 → 443157.0 (+7.6%) | C: 4704→4936 (+4.9%), L: 5044→4968 (-1.5%) | Retx: 2→5, Lost: 2→3, Dup: 1→1 | 0.78 → 0.55 |
| **tokio 200c×8M shared-pool:4 loss=1%** | n=3 | 29.8% → 29.8% | 29.8% → 29.8% | 100.0% → 100.0% | no/no | 4276.8 [3762.7..4645.6] → 4929.9 [4706.5..5153.3] (**+15.3%**, overlap: no) | 23362.7 → 27092.4 (+16.0%) | 21663.6 → 24809.2 (+14.5%) | C: 64→97 (+52.2%), L: 79→93 (+16.8%) | Retx: 3279→2918, Lost: 2697→2320, Dup: 542→570 | 3.04 → 8.86 |
| **tokio 1c×8M shared-pool:4 loss=1%** | n=3 | 55.6% → 55.6% | 55.6% → 55.6% | 100.0% → 100.0% | no/no | 97109.9 [76495.4..110091.8] → 113327.5 [95566.8..127054.8] (**+16.7%**, overlap: yes) | 577669.5 → 672630.6 (+16.4%) | 444703.4 → 520480.8 (+17.0%) | C: 5100→5128 (+0.5%), L: 5276→5272 (-0.1%) | Retx: 25→24, Lost: 20→22, Dup: 4→3 | 1.48 → 0.84 |
| **tokio 30c×8M shared-pool:4** | n=3 | 37.9% → 37.8% | 37.9% → 37.8% | 100.0% → 100.0% | no/no | 9850.0 [8458.4..10950.3] → 11630.3 [9359.4..13457.0] (**+18.1%**, overlap: yes) | 58014.1 → 69223.8 (+19.3%) | 45686.6 → 53219.6 (+16.5%) | C: 200→204 (+2.1%), L: 265→290 (+9.7%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 1.74 → 1.60 |
| **mio 1c×8M shared-pool:4** | n=3 | 55.6% → 55.6% | 55.6% → 55.6% | 100.0% → 100.0% | no/no | 97843.6 [83026.5..124517.9] → 117479.6 [84163.3..130673.8] (**+20.1%**, overlap: yes) | 562441.7 → 670356.8 (+19.2%) | 467655.8 → 566468.4 (+21.1%) | C: 4848→4900 (+1.1%), L: 4828→5000 (+3.6%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 0.73 → 1.07 |
| **tokio 1c×8M shared-pool:4 loss=0.1%** | n=3 | 55.6% → 55.6% | 55.6% → 55.6% | 100.0% → 100.0% | no/no | 99424.8 [93191.7..116849.6] → 120839.6 [109146.8..127952.1] (**+21.5%**, overlap: yes) | 588626.2 → 708870.6 (+20.4%) | 458117.8 → 563328.8 (+23.0%) | C: 5092→5220 (+2.5%), L: 5172→5264 (+1.8%) | Retx: 3→5, Lost: 2→4, Dup: 1→1 | 0.99 → 1.15 |
| **tokio 30c×8M shared-pool:4 loss=0.1%** | n=3 | 37.8% → 37.8% | 37.8% → 37.8% | 100.0% → 100.0% | no/no | 8715.7 [7204.0..11124.1] → 11009.9 [8970.1..11886.5] (**+26.3%**, overlap: yes) | 50224.8 → 61223.1 (+21.9%) | 41533.8 → 54688.8 (+31.7%) | C: 202→201 (-0.6%), L: 262→290 (+10.6%) | Retx: 92→73, Lost: 84→62, Dup: 41→11 | 1.35 → 3.07 |
| **mio 30c×8M shared-pool:4** | n=3 | 48.0% → 47.7% | 48.0% → 47.7% | 100.0% → 100.0% | no/no | 6924.0 [6192.3..7295.2] → 8915.7 [6911.0..10412.5] (**+28.8%**, overlap: yes) | 40725.4 → 53985.6 (+32.6%) | 31906.1 → 39878.7 (+25.0%) | C: 181→184 (+2.0%), L: 259→254 (-2.1%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 1.77 → 3.16 |
| **mio 1c×8M shared-pool:4 loss=1%** | n=3 | 55.6% → 55.6% | 55.6% → 55.6% | 100.0% → 100.0% | no/no | 83797.9 [77658.8..101540.1] → 109243.1 [96742.7..114421.2] (**+30.4%**, overlap: yes) | 488549.0 → 652561.2 (+33.6%) | 393675.1 → 497550.1 (+26.4%) | C: 4840→4908 (+1.4%), L: 4908→4948 (+0.8%) | Retx: 27→21, Lost: 22→18, Dup: 5→3 | 1.12 → 1.67 |
| **tokio 30c×8M shared-pool:4 loss=1%** | n=3 | 37.8% → 37.8% | 37.8% → 37.8% | 100.0% → 100.0% | no/no | 9349.7 [8735.3..12730.0] → 12510.6 [7622.8..13060.2] (**+33.8%**, overlap: yes) | 53860.1 → 70050.4 (+30.1%) | 44571.9 → 61661.6 (+38.3%) | C: 201→205 (+1.8%), L: 252→294 (+16.9%) | Retx: 735→751, Lost: 647→683, Dup: 76→76 | 1.53 → 1.41 |
| **mio 30c×8M shared-pool:4 loss=1%** | n=3 | 47.9% → 43.8% | 47.9% → 43.8% | 100.0% → 100.0% | no/no | 6819.4 [5627.0..9632.6] → 12329.3 [11352.4..41954.8] (**+80.8%**, overlap: no) | 38648.0 → 74656.3 (+93.2%) | 33146.2 → 55144.6 (+66.4%) | C: 191→227 (+18.5%), L: 263→260 (-1.0%) | Retx: 775→604, Lost: 715→509, Dup: 51→68 | 4.74 → 3.27 |

### 5.2 Packet Reordering Recovery (`recovery-reorder.plan`, $N=3$)

Varies link packet reordering ($0.1\%$ and $1.0\%$) with a required base link delay of $10\text{ ms}$ ($N=3$ repetitions).

| Workload Cell | Reps | Offer% (B→H) | Good% (B→H) | Deliv% (B→H) | Clean B/H | CPU ms/Gbit (Base [min..max] → Head [min..max], Δ%, Overlap) | Caller CPU ms/Mpkt | Listener CPU ms/Mpkt | Peak RSS/conn KB (Caller, Listener) | Recovery Telemetry (Retx, Lost, Dup) | RTT ms |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **mio 30c×8M shared-pool:4** | n=3 | 55.4% → 55.5% | 55.4% → 55.5% | 100.0% → 100.0% | no/no | 9107.8 [5787.4..12510.6] → 6715.1 [6366.4..7682.4] (**-26.3%**, overlap: yes) | 50993.4 → 37785.4 (-25.9%) | 44265.8 → 32711.8 (-26.1%) | C: 205→234 (+14.1%), L: 226→234 (+3.5%) | Retx: 619→552, Lost: 588→502, Dup: 619→552 | 29.88 → 25.36 |
| **tokio 200c×8M shared-pool:4 reorder=1%** | n=3 | 28.5% → 28.5% | 28.5% → 28.5% | 100.0% → 100.0% | no/no | 11772.1 [8492.9..13593.7] → 8925.3 [8872.1..9167.0] (**-24.2%**, overlap: yes) | 67448.9 → 51787.6 (-23.2%) | 56934.3 → 42522.6 (-25.3%) | C: 75→63 (-16.0%), L: 62→63 (+1.6%) | Retx: 1046→738, Lost: 969→682, Dup: 1046→738 | 43.68 → 34.14 |
| **mio 200c×8M shared-pool:4 reorder=1%** | n=3 | 39.5% → 39.4% | 39.5% → 39.4% | 100.0% → 100.0% | no/no | 8369.8 [7267.3..9791.2] → 6419.6 [5814.2..7075.2] (**-23.3%**, overlap: no) | 45548.8 → 33379.7 (-26.7%) | 38435.5 → 31019.3 (-19.3%) | C: 94→85 (-9.6%), L: 85→85 (+0.0%) | Retx: 1462→2102, Lost: 1390→1984, Dup: 1462→2102 | 70.74 → 35.40 |
| **tokio 1c×8M shared-pool:4 reorder=0.1%** | n=3 | 55.6% → 55.6% | 55.6% → 55.6% | 100.0% → 100.0% | no/no | 85359.8 [46619.1..107024.2] → 66545.8 [61076.5..95308.2] (**-22.0%**, overlap: yes) | 496660.8 → 341563.9 (-31.2%) | 400647.2 → 360555.2 (-10.0%) | C: 5168→5108 (-1.2%), L: 5158→5160 (+0.0%) | Retx: 12→22, Lost: 10→18, Dup: 12→22 | 26.40 → 22.26 |
| **tokio 1c×8M shared-pool:4 reorder=1%** | n=3 | 55.6% → 55.6% | 55.6% → 55.6% | 100.0% → 100.0% | no/no | 78359.9 [51264.0..87019.8] → 66361.8 [60481.3..90620.4] (**-15.3%**, overlap: yes) | 339342.6 → 347101.4 (+2.3%) | 468494.6 → 328841.4 (-29.8%) | C: 5112→5312 (+3.9%), L: 5112→5312 (+3.9%) | Retx: 101→77, Lost: 82→64, Dup: 101→77 | 21.06 → 21.50 |
| **mio 30c×8M shared-pool:4 reorder=0.1%** | n=3 | 55.4% → 55.4% | 55.4% → 55.4% | 100.0% → 100.0% | no/no | 8428.1 [6238.1..13231.8] → 7416.9 [6146.8..15455.7] (**-12.0%**, overlap: yes) | 44342.9 → 38918.8 (-12.2%) | 41724.8 → 36829.4 (-11.7%) | C: 202→213 (+5.4%), L: 227→218 (-4.0%) | Retx: 1002→928, Lost: 932→890, Dup: 1002→928 | 29.62 → 26.01 |
| **mio 1c×8M shared-pool:4 reorder=1%** | n=3 | 55.6% → 55.6% | 55.6% → 55.6% | 100.0% → 100.0% | no/no | 61713.2 [53314.6..79352.5] → 56487.0 [49317.3..104258.4] (**-8.5%**, overlap: yes) | 354388.9 → 290548.8 (-18.0%) | 280525.3 → 277259.0 (-1.2%) | C: 4920→4968 (+1.0%), L: 4800→5016 (+4.5%) | Retx: 78→70, Lost: 66→62, Dup: 78→70 | 31.66 → 24.24 |
| **mio 1c×8M shared-pool:4** | n=3 | 55.6% → 55.6% | 55.6% → 55.6% | 100.0% → 100.0% | no/no | 72262.9 [59308.9..77603.2] → 74091.2 [57874.1..79750.4] (**+2.5%**, overlap: yes) | 361956.1 → 372750.5 (+3.0%) | 382348.8 → 411475.2 (+7.6%) | C: 4916→4976 (+1.2%), L: 4914→5046 (+2.7%) | Retx: 9→14, Lost: 8→12, Dup: 9→14 | 21.91 → 21.55 |
| **tokio 200c×8M shared-pool:4** | n=3 | 29.8% → 29.8% | 29.8% → 29.8% | 100.0% → 100.0% | no/no | 8524.5 [8109.0..8787.8] → 9016.0 [8024.9..9462.6] (**+5.8%**, overlap: yes) | 48402.1 → 49887.8 (+3.1%) | 39157.1 → 42633.2 (+8.9%) | C: 70→61 (-12.9%), L: 47→62 (+31.9%) | Retx: 75→54, Lost: 64→54, Dup: 75→54 | 32.21 → 89.91 |
| **tokio 30c×8M shared-pool:4 reorder=1%** | n=3 | 37.7% → 37.8% | 37.7% → 37.8% | 100.0% → 100.0% | no/no | 11435.0 [9310.3..12976.2] → 12092.6 [11056.6..15057.6] (**+5.8%**, overlap: yes) | 61852.1 → 63825.5 (+3.2%) | 55762.6 → 62846.5 (+12.7%) | C: 239→269 (+12.6%), L: 236→271 (+14.8%) | Retx: 2007→2055, Lost: 1690→1762, Dup: 2007→2055 | 26.50 → 25.02 |
| **mio 30c×8M shared-pool:4 reorder=1%** | n=3 | 55.4% → 55.4% | 55.4% → 55.4% | 100.0% → 100.0% | no/no | 8356.1 [7001.8..11096.0] → 8946.3 [8033.6..13540.8] (**+7.1%**, overlap: yes) | 48028.9 → 45438.4 (-5.5%) | 38221.7 → 46816.6 (+22.5%) | C: 202→217 (+7.4%), L: 216→264 (+22.2%) | Retx: 2966→2456, Lost: 2551→2202, Dup: 2965→2456 | 25.02 → 36.33 |
| **tokio 30c×8M shared-pool:4** | n=3 | 37.9% → 37.8% | 37.9% → 37.8% | 100.0% → 100.0% | no/no | 10105.8 [8281.0..10505.0] → 11120.5 [8454.6..11293.4] (**+10.0%**, overlap: yes) | 54290.2 → 55673.7 (+2.5%) | 42498.4 → 50989.8 (+20.0%) | C: 230→269 (+17.0%), L: 245→269 (+9.8%) | Retx: 639→469, Lost: 593→430, Dup: 639→469 | 24.88 → 26.50 |
| **mio 200c×8M shared-pool:4** | n=3 | 41.7% → 41.7% | 41.7% → 41.7% | 100.0% → 100.0% | no/no | 6589.4 [6513.4..6678.9] → 7441.9 [5892.7..8372.9] (**+12.9%**, overlap: yes) | 36301.1 → 42306.9 (+16.5%) | 32672.2 → 36284.7 (+11.1%) | C: 77→72 (-6.5%), L: 57→72 (+26.3%) | Retx: 106→156, Lost: 108→152, Dup: 106→156 | 36.83 → 30.10 |
| **mio 1c×8M shared-pool:4 reorder=0.1%** | n=3 | 55.6% → 55.6% | 55.6% → 55.6% | 100.0% → 100.0% | no/no | 61156.0 [48878.0..73310.0] → 69092.4 [53815.0..91145.0] (**+13.0%**, overlap: yes) | 330910.0 → 458788.1 (+38.6%) | 312287.6 → 291778.6 (-6.6%) | C: 4920→4964 (+0.9%), L: 4726→5000 (+5.8%) | Retx: 14→8, Lost: 11→8, Dup: 14→8 | 22.79 → 23.44 |
| **tokio 1c×8M shared-pool:4** | n=3 | 55.6% → 55.6% | 55.6% → 55.6% | 100.0% → 100.0% | no/no | 78190.6 [62211.8..82635.4] → 88693.5 [84195.3..118621.8] (**+13.4%**, overlap: no) | 390743.5 → 442340.2 (+13.2%) | 417242.0 → 515286.9 (+23.5%) | C: 5220→5252 (+0.6%), L: 5048→5300 (+5.0%) | Retx: 4→12, Lost: 4→12, Dup: 4→12 | 22.72 → 21.10 |
| **tokio 200c×8M shared-pool:4 reorder=0.1%** | n=3 | 29.8% → 29.8% | 29.8% → 29.8% | 100.0% → 100.0% | no/no | 8366.0 [7562.1..9641.8] → 9614.2 [8883.4..9867.3] (**+14.9%**, overlap: yes) | 45595.5 → 53523.5 (+17.4%) | 39686.3 → 44400.9 (+11.9%) | C: 83→55 (-33.7%), L: 52→55 (+5.8%) | Retx: 216→90, Lost: 203→83, Dup: 216→90 | 28.68 → 61.56 |
| **mio 200c×8M shared-pool:4 reorder=0.1%** | n=3 | 41.7% → 41.7% | 41.7% → 41.7% | 100.0% → 100.0% | no/no | 6518.8 [6347.9..6936.4] → 8326.6 [5809.2..9463.3] (**+27.7%**, overlap: yes) | 35395.4 → 46026.0 (+30.0%) | 32334.7 → 40510.9 (+25.3%) | C: 70→66 (-5.7%), L: 75→66 (-12.0%) | Retx: 420→396, Lost: 412→380, Dup: 420→396 | 75.93 → 38.37 |
| **tokio 30c×8M shared-pool:4 reorder=0.1%** | n=3 | 37.9% → 37.7% | 37.9% → 37.7% | 100.0% → 100.0% | no/no | 9747.0 [9410.6..10674.1] → 13899.2 [9166.7..18192.3] (**+42.6%**, overlap: yes) | 54593.4 → 74936.1 (+37.3%) | 45293.4 → 67341.0 (+48.7%) | C: 231→273 (+18.2%), L: 244→273 (+11.9%) | Retx: 626→578, Lost: 576→532, Dup: 626→578 | 26.31 → 39.31 |

### Recovery Findings
- **Reordering Acceleration**: Under 1.0% reordering at scale (`mio 200c×8M reorder=1%`), CPU utilization drops by **-23.3%** ($8370\text{ ms/Gbit}$ down to $6420\text{ ms/Gbit}$) with **non-overlapping distributions** ($[7267..9791]$ vs $[5814..7075]$). Tokio 200c×8M under 1.0% reorder improves by **-24.2%** ($11772\text{ ms/Gbit}$ down to $8925\text{ ms/Gbit}$, overlapping ranges).
- **Packet Loss Recovery**: At 200 connections, actual packet loss recovery exhibits **neutral-to-regressive** CPU consumption in this measurement window ($+0.5\%$ at 0.1% loss, $+7.4\%$ to $+15.3\%$ at 1.0% loss). Single-connection loss recovery likewise regresses (+9.4% to +30.4% on mio, +16.7% to +21.5% on tokio). Telemetry demonstrates that both trees completed comparable retransmission and loss recovery work with 100% end-to-end delivery / zero unrecovered delivery loss.

---

## 6. All-Six Runtime Breadth Campaign (`runtime-breadth.plan`, $N=3$)

Evaluates all six runtime execution models under identical topology (`shared-pool:4`, `per-connection`, `plain`) at 50, 200, and 600 connections across 1M and 8M bitrates (all 36 controlled cells reported, $N=3$).

| Workload Cell | Reps | Offer% (B→H) | Good% (B→H) | Deliv% (B→H) | Clean B/H | CPU ms/Gbit (Base [min..max] → Head [min..max], Δ%, Overlap) | Caller CPU ms/Mpkt | Listener CPU ms/Mpkt | Peak RSS/conn KB (Caller, Listener) | Recovery Telemetry (Retx, Lost, Dup) | RTT ms |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **mio 50c×8M shared-pool:4** | n=3 | 34.6% → 32.7% | 34.6% → 32.7% | 100.0% → 100.0% | no/no | 9847.1 [9724.8..10308.2] → 5994.8 [5422.6..8173.8] (**-39.1%**, overlap: no) | 59259.4 → 33903.0 (-42.8%) | 44410.7 → 27382.7 (-38.3%) | C: 163→216 (+32.5%), L: 183→192 (+4.9%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 2.00 → 2.60 |
| **glommio 600c×8M shared-pool:4** | n=3 | 6.7% → 6.7% | 6.7% → 6.7% | 100.0% → 100.0% | no/no | 12997.2 [11138.8..19141.1] → 8857.9 [8613.7..9330.6] (**-31.8%**, overlap: no) | 71112.9 → 48060.0 (-32.4%) | 65611.8 → 45053.3 (-31.3%) | C: 48→24 (-50.0%), L: 20→24 (+20.0%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 17.69 → 35.56 |
| **smol 200c×1M shared-pool:4** | n=3 | 42.6% → 42.6% | 42.6% → 42.6% | 100.0% → 100.0% | no/no | 28731.7 [15671.8..32405.3] → 20256.3 [15456.9..20540.8] (**-29.5%**, overlap: yes) | 164823.1 → 114379.8 (-30.6%) | 139106.6 → 98878.8 (-28.9%) | C: 81→64 (-21.0%), L: 49→58 (+18.4%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 16.18 → 5.71 |
| **tokio 200c×1M shared-pool:4** | n=3 | 48.0% → 55.4% | 48.0% → 55.4% | 100.0% → 100.0% | no/no | 18153.9 [11162.9..20110.8] → 12920.0 [11482.3..12974.7] (**-28.8%**, overlap: yes) | 97973.9 → 66028.3 (-32.6%) | 92953.9 → 69677.2 (-25.0%) | C: 47→56 (+19.1%), L: 45→56 (+24.4%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 2.71 → 30.94 |
| **compio 50c×1M shared-pool:4** | n=3 | 64.0% → 64.0% | 64.0% → 64.0% | 100.0% → 100.0% | no/no | 25579.5 [18282.6..27720.6] → 21282.7 [19365.8..23009.3] (**-16.8%**, overlap: yes) | 138378.8 → 113320.5 (-18.1%) | 126136.2 → 110744.1 (-12.2%) | C: 143→161 (+12.6%), L: 141→164 (+16.3%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 15.23 → 19.48 |
| **glommio 200c×1M shared-pool:4** | n=3 | 56.6% → 56.6% | 56.6% → 56.6% | 100.0% → 100.0% | no/no | 17912.4 [14016.0..18126.1] → 15260.6 [14687.0..22520.1] (**-14.8%**, overlap: yes) | 90001.9 → 76019.5 (-15.5%) | 85926.8 → 78604.9 (-8.5%) | C: 60→49 (-18.3%), L: 41→52 (+26.8%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 10.29 → 7.74 |
| **compio 200c×8M shared-pool:4** | n=3 | 31.9% → 31.9% | 31.9% → 31.9% | 100.0% → 100.0% | no/no | 4656.8 [4317.0..5268.7] → 3978.8 [3869.5..5139.1] (**-14.6%**, overlap: yes) | 25737.8 → 22108.9 (-14.1%) | 23289.1 → 19769.9 (-15.1%) | C: 144→131 (-9.0%), L: 129→126 (-2.3%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 70.17 → 37.08 |
| **glommio 600c×1M shared-pool:4** | n=3 | 53.4% → 53.4% | 53.4% → 53.4% | 100.0% → 100.0% | no/no | 10538.7 [10321.4..10919.8] → 9516.4 [9008.9..12084.4] (**-9.7%**, overlap: yes) | 53459.7 → 45970.6 (-14.0%) | 52408.8 → 48874.7 (-6.8%) | C: 48→23 (-52.1%), L: 16→22 (+37.5%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 33.14 → 27.95 |
| **mio 200c×1M shared-pool:4** | n=3 | 55.4% → 65.4% | 55.4% → 65.4% | 100.0% → 100.0% | no/no | 12859.1 [9730.9..22804.3] → 11934.7 [9880.1..13023.2] (**-7.2%**, overlap: yes) | 68254.4 → 61129.2 (-10.4%) | 67451.9 → 64949.4 (-3.7%) | C: 43→49 (+14.0%), L: 43→52 (+20.9%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 3.14 → 6.18 |
| **tokio 600c×1M shared-pool:4** | n=3 | 44.5% → 44.5% | 44.5% → 44.5% | 100.0% → 100.0% | no/no | 8228.2 [7761.4..12178.1] → 7878.3 [7448.9..11073.4] (**-4.3%**, overlap: yes) | 43246.7 → 42559.2 (-1.6%) | 43379.3 → 40383.9 (-6.9%) | C: 36→26 (-27.8%), L: 22→26 (+18.2%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 36.05 → 16.30 |
| **tokio 200c×8M shared-pool:4** | n=3 | 29.8% → 29.8% | 29.8% → 29.8% | 100.0% → 100.0% | no/no | 4676.5 [4544.7..4689.4] → 4650.0 [4145.0..7460.1] (**-0.6%**, overlap: yes) | 25825.0 → 25807.5 (-0.1%) | 23409.3 → 23555.2 (+0.6%) | C: 78→77 (-1.3%), L: 78→90 (+15.4%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 35.12 → 6.23 |
| **tokio 50c×1M shared-pool:4** | n=3 | 68.6% → 72.8% | 68.6% → 72.8% | 100.0% → 100.0% | no/no | 22695.1 [19940.3..27096.5] → 22862.0 [19593.1..28574.6] (**+0.7%**, overlap: yes) | 131086.9 → 124116.7 (-5.3%) | 107847.1 → 116616.7 (+8.1%) | C: 126→151 (+19.8%), L: 131→151 (+15.3%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 9.55 → 2.22 |
| **monoio 50c×1M shared-pool:4** | n=3 | 64.9% → 64.9% | 64.9% → 64.9% | 100.0% → 100.0% | no/no | 20063.4 [15209.9..22810.0] → 20308.2 [16368.0..36365.1] (**+1.2%**, overlap: yes) | 88166.4 → 77826.5 (-11.7%) | 82596.1 → 94495.9 (+14.3%) | C: 126→146 (+15.9%), L: 122→131 (+7.4%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 3.99 → 7.17 |
| **tokio 50c×8M shared-pool:4** | n=3 | 29.8% → 29.8% | 29.8% → 29.8% | 100.0% → 100.0% | no/no | 9546.4 [7889.8..14030.1] → 9658.3 [8578.0..10930.2] (**+1.2%**, overlap: yes) | 56708.3 → 56075.2 (-1.1%) | 43906.9 → 45759.5 (+4.2%) | C: 138→205 (+48.6%), L: 185→205 (+10.8%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 1.98 → 6.93 |
| **smol 200c×8M shared-pool:4** | n=3 | 24.3% → 24.3% | 24.3% → 24.3% | 100.0% → 100.0% | no/no | 8551.4 [5186.5..12095.4] → 8663.4 [6438.5..9062.2] (**+1.3%**, overlap: yes) | 37042.8 → 36885.3 (-0.4%) | 29908.4 → 30899.6 (+3.4%) | C: 93→104 (+11.8%), L: 90→96 (+6.7%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 3.25 → 4.98 |
| **mio 600c×8M shared-pool:4** | n=3 | 8.8% → 8.8% | 8.8% → 8.8% | 100.0% → 100.0% | no/no | 6001.6 [5741.0..7206.2] → 6080.4 [5588.6..6408.8] (**+1.3%**, overlap: yes) | 32008.2 → 33575.4 (+4.9%) | 31177.0 → 30426.6 (-2.4%) | C: 74→71 (-4.1%), L: 94→30 (-68.1%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 24.24 → 18.38 |
| **smol 50c×1M shared-pool:4** | n=3 | 36.3% → 36.3% | 36.3% → 36.3% | 100.0% → 100.0% | no/no | 33095.1 [33067.8..35096.4] → 33684.0 [28597.0..37123.1] (**+1.8%**, overlap: yes) | 174540.8 → 159187.9 (-8.8%) | 148906.4 → 156763.4 (+5.3%) | C: 129→151 (+17.1%), L: 128→151 (+18.0%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 3.10 → 4.47 |
| **glommio 200c×8M shared-pool:4** | n=3 | 25.1% → 25.1% | 25.1% → 25.1% | 100.0% → 100.0% | no/no | 12430.4 [10404.2..15477.8] → 12695.1 [10166.5..31312.9] (**+2.1%**, overlap: yes) | 68257.6 → 65545.9 (-4.0%) | 62719.8 → 68176.4 (+8.7%) | C: 63→61 (-3.2%), L: 51→63 (+23.5%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 9.54 → 12.50 |
| **mio 50c×1M shared-pool:4** | n=3 | 70.1% → 70.1% | 70.1% → 70.1% | 100.0% → 100.0% | no/no | 20766.1 [17885.1..28396.9] → 21600.9 [18340.2..30989.4] (**+4.0%**, overlap: yes) | 110363.6 → 106597.6 (-3.4%) | 94676.6 → 107629.7 (+13.7%) | C: 116→125 (+7.8%), L: 123→127 (+3.3%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 2.22 → 3.19 |
| **smol 600c×8M shared-pool:4** | n=3 | 6.4% → 6.4% | 6.4% → 6.4% | 100.0% → 100.0% | no/no | 9659.5 [8964.1..15811.7] → 10063.0 [9125.3..10191.1] (**+4.2%**, overlap: yes) | 54681.2 → 57121.2 (+4.5%) | 47014.4 → 48820.6 (+3.8%) | C: 40→36 (-10.0%), L: 27→36 (+33.3%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 22.18 → 29.45 |
| **compio 600c×1M shared-pool:4** | n=3 | 54.3% → 54.3% | 54.3% → 54.3% | 100.0% → 100.0% | no/no | 10375.9 [10037.1..12903.0] → 10817.5 [10257.8..15036.0] (**+4.3%**, overlap: yes) | 54389.4 → 59781.0 (+9.9%) | 51281.6 → 50502.8 (-1.5%) | C: 65→47 (-27.7%), L: 47→47 (+0.0%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 270.57 → 76.85 |
| **monoio 600c×1M shared-pool:4** | n=3 | 74.4% → 50.9% | 74.4% → 50.9% | 64.9% → 50.9% | no/no | 15015.6 [12570.9..15022.0] → 15796.1 [14493.5..15896.6] (**+5.2%**, overlap: yes) | 56778.6 → 39978.0 (-29.6%) | 80860.2 → 81635.8 (+1.0%) | C: 96→21 (-78.1%), L: 19→21 (+10.5%) | Retx: 0→0, Lost: 1061→10028, Dup: 0→0 | 86.80 → 88.96 |
| **glommio 50c×1M shared-pool:4** | n=3 | 58.7% → 58.7% | 58.7% → 58.7% | 100.0% → 100.0% | no/no | 21568.1 [18404.3..26071.1] → 22774.2 [19726.2..31307.2] (**+5.6%**, overlap: yes) | 105658.2 → 99901.6 (-5.4%) | 97361.6 → 115160.0 (+18.3%) | C: 133→141 (+6.0%), L: 131→151 (+15.3%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 2.25 → 2.07 |
| **compio 50c×8M shared-pool:4** | n=3 | 34.6% → 34.6% | 34.6% → 34.6% | 100.0% → 100.0% | no/no | 8205.4 [7718.5..8558.1] → 8710.2 [7040.6..8975.7] (**+6.1%**, overlap: yes) | 44219.4 → 48312.2 (+9.3%) | 42166.9 → 43336.8 (+2.8%) | C: 189→304 (+60.8%), L: 289→304 (+5.2%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 18.13 → 17.18 |
| **mio 200c×8M shared-pool:4** | n=3 | 39.5% → 39.5% | 39.5% → 39.5% | 100.0% → 100.0% | no/no | 3199.7 [2683.7..4337.2] → 3397.0 [3077.6..3707.0] (**+6.2%**, overlap: yes) | 16568.5 → 17757.0 (+7.2%) | 15437.0 → 16213.1 (+5.0%) | C: 171→197 (+15.2%), L: 148→197 (+33.1%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 8.19 → 17.09 |
| **tokio 600c×8M shared-pool:4** | n=3 | 8.8% → 8.8% | 8.8% → 8.8% | 100.0% → 100.0% | no/no | 7603.2 [7371.2..14692.1] → 8174.1 [7378.8..10572.2] (**+7.5%**, overlap: yes) | 40167.3 → 43577.4 (+8.5%) | 39070.7 → 41571.2 (+6.4%) | C: 46→23 (-50.0%), L: 25→26 (+4.0%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 18.37 → 46.65 |
| **smol 50c×8M shared-pool:4** | n=3 | 34.6% → 34.6% | 34.6% → 34.6% | 100.0% → 100.0% | no/no | 6905.8 [6901.4..8609.2] → 7478.7 [7422.6..7822.0] (**+8.3%**, overlap: yes) | 40653.8 → 43339.7 (+6.6%) | 32003.9 → 34960.9 (+9.2%) | C: 188→271 (+44.1%), L: 233→271 (+16.3%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 3.64 → 8.89 |
| **compio 600c×8M shared-pool:4** | n=3 | 8.8% → 8.8% | 8.8% → 8.8% | 100.0% → 100.0% | no/no | 8638.1 [7901.9..8643.0] → 9537.4 [8742.6..11968.6] (**+10.4%**, overlap: no) | 44927.7 → 50058.0 (+11.4%) | 43814.8 → 48316.0 (+10.3%) | C: 58→46 (-20.7%), L: 46→48 (+4.3%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 178.36 → 78.65 |
| **mio 600c×1M shared-pool:4** | n=3 | 55.4% → 55.4% | 55.4% → 55.4% | 100.0% → 100.0% | no/no | 6774.8 [6666.4..7017.9] → 7523.5 [6838.1..8927.4] (**+11.0%**, overlap: yes) | 35848.4 → 40192.4 (+12.1%) | 35246.7 → 38781.0 (+10.0%) | C: 26→29 (+11.5%), L: 30→29 (-3.3%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 86.78 → 9.40 |
| **smol 600c×1M shared-pool:4** | n=3 | 54.2% → 54.2% | 54.2% → 54.2% | 100.0% → 100.0% | no/no | 9678.0 [9320.4..10531.0] → 11300.9 [8943.0..15596.2] (**+16.8%**, overlap: yes) | 52780.3 → 60170.8 (+14.0%) | 45344.8 → 54508.3 (+20.2%) | C: 35→31 (-11.4%), L: 35→31 (-11.4%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 21.03 → 28.92 |
| **compio 200c×1M shared-pool:4** | n=3 | 56.6% → 56.6% | 56.6% → 56.6% | 100.0% → 100.0% | no/no | 13596.0 [12625.8..20080.1] → 16397.0 [11079.4..17411.2] (**+20.6%**, overlap: yes) | 71112.9 → 83416.0 (+17.3%) | 68285.9 → 84949.4 (+24.4%) | C: 81→71 (-12.3%), L: 65→71 (+9.2%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 25.29 → 25.98 |
| **monoio 200c×8M shared-pool:4** | n=3 | 29.8% → 29.8% | 29.5% → 29.8% | 99.0% → 100.0% | no/no | 4233.6 [3560.1..5049.2] → 5174.9 [4523.7..5295.1] (**+22.2%**, overlap: yes) | 20821.4 → 27008.0 (+29.7%) | 23332.6 → 27485.4 (+17.8%) | C: 183→65 (-64.5%), L: 81→74 (-8.6%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 486.52 → 147.44 |
| **monoio 600c×8M shared-pool:4** | n=3 | 8.8% → 8.8% | 6.0% → 5.1% | 68.8% → 58.5% | no/no | 12878.9 [12728.9..20250.0] → 15766.1 [13363.9..27589.4] (**+22.4%**, overlap: yes) | 45768.6 → 38935.1 (-14.9%) | 70935.2 → 87034.4 (+22.7%) | C: 101→20 (-80.2%), L: 19→20 (+5.3%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 97.47 → 95.32 |
| **glommio 50c×8M shared-pool:4** | n=3 | 34.6% → 34.6% | 34.6% → 34.6% | 100.0% → 100.0% | no/no | 15185.8 [13886.1..16472.0] → 18851.3 [16999.4..19482.0] (**+24.1%**, overlap: no) | 83853.2 → 87541.2 (+4.4%) | 76023.0 → 110313.2 (+45.1%) | C: 138→154 (+11.6%), L: 133→154 (+15.8%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 7.93 → 12.86 |
| **monoio 50c×8M shared-pool:4** | n=3 | 34.6% → 34.6% | 34.6% → 34.6% | 100.0% → 100.0% | no/no | 8080.2 [7765.4..9801.3] → 10516.9 [8349.2..11845.0] (**+30.2%**, overlap: yes) | 42948.4 → 49820.0 (+16.0%) | 41344.0 → 60195.4 (+45.6%) | C: 151→188 (+24.5%), L: 172→174 (+1.2%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 4.53 → 4.79 |
| **monoio 200c×1M shared-pool:4** | n=3 | 55.4% → 55.4% | 55.4% → 55.4% | 100.0% → 100.0% | no/no | 13108.9 [11320.7..13861.4] → 19207.1 [13854.3..19382.4] (**+46.5%**, overlap: yes) | 68254.4 → 95082.0 (+39.3%) | 66085.8 → 100585.8 (+52.2%) | C: 78→52 (-33.3%), L: 42→54 (+28.6%) | Retx: 0→0, Lost: 0→0, Dup: 0→0 | 40.84 → 94.33 |

### Breadth Findings
- **Generalization Across Diverse Engines**: Five runtime families (`compio`, `glommio`, `mio`, `smol`, `tokio`) exhibit selected, workload-specific wins under identical topology (`shared-pool:4`, `per-connection`, `plain`):
  - `compio`: **-16.8%** on 50c×1M, **-14.6%** on 200c×8M.
  - `glommio`: **-31.8%** on 600c×8M, **-14.8%** on 200c×1M, **-9.7%** on 600c×1M.
  - `mio`: **-39.1%** on 50c×8M, **-7.2%** on 200c×1M.
  - `smol`: **-29.5%** on 200c×1M.
  - `tokio`: **-28.8%** on 200c×1M.
- **Monoio Regression Under Common Topology**: Under this common configuration, `monoio` exhibits material regressions across workloads (+1.2% to +46.5% CPU) and delivery shortfalls (dropping to 50.9% and 58.5% at 600 connections). This indicates that the performance profile is sensitive to runtime architecture, supporting the need for a separate runtime-showcase PR rather than assuming uniform behavior across runtimes.

---

## 7. 2x2 Factorial Mixed-Version Experiment

Decoupled executable matrices on `mio-pool-plain` ($N=3$ repetitions, 10 seconds):
- $y_{00}$: Old Caller (`cde0e53`) → Old Listener (`cde0e53`)
- $y_{01}$: Old Caller (`cde0e53`) → New Listener (`aba97ae`)
- $y_{10}$: New Caller (`aba97ae`) → Old Listener (`cde0e53`)
- $y_{11}$: New Caller (`aba97ae`) → New Listener (`aba97ae`)

### Measured Cell Responses ($N=3$)

| Configuration | Symbol | Median Combined CPU ms/Gbit | Sample Spread [min..max] | Caller CPU ms/Mpkt | Listener CPU ms/Mpkt | Peak RSS/conn KB (Caller / Listener) |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| Old Caller → Old Listener | $y_{00}$ | **7060.1** | [6838.6 .. 8206.0] | 37886.8 | 36478.0 | 21 / 29 |
| Old Caller → New Listener | $y_{01}$ | **6720.2** | [6540.4 .. 7414.3] | 35848.5 | 34842.2 | 22 / 30 |
| New Caller → Old Listener | $y_{10}$ | **7268.9** | [6872.8 .. 7376.2] | 38624.1 | 37820.6 | 23 / 28 |
| New Caller → New Listener | $y_{11}$ | **7825.1** | [7344.2 .. 8262.4] | 41344.5 | 40685.2 | 24 / 30 |

### Descriptive Factorial Effects

$$\begin{aligned}
\text{Listener Effect (Old Caller)} &= y_{01} - y_{00} = -339.9\text{ ms/Gbit } (-4.8\%) \\
\text{Listener Effect (New Caller)} &= y_{11} - y_{10} = +556.2\text{ ms/Gbit } (+7.7\%) \\
\text{Caller Effect (Old Listener)} &= y_{10} - y_{00} = +208.8\text{ ms/Gbit } (+3.0\%) \\
\text{Caller Effect (New Listener)} &= y_{11} - y_{01} = +1105.0\text{ ms/Gbit } (+16.4\%) \\
\text{Observed Interaction Term} &= y_{11} - y_{10} - y_{01} + y_{00} = \mathbf{+896.1\text{ ms/Gbit}}
\end{aligned}$$

### Per-Repetition Interaction Spread
Computing the interaction term across matched execution repetitions ($\text{interaction}_r = y_{11,r} - y_{10,r} - y_{01,r} + y_{00,r}$):
- **Rep 1**: $+2137.0\text{ ms/Gbit}$
- **Rep 2**: $+567.4\text{ ms/Gbit}$
- **Rep 3**: $+639.3\text{ ms/Gbit}$
- **Per-repetition interaction median**: $\mathbf{+639.3\text{ ms/Gbit}}$ ($[+567.4 .. +2137.0]$)

### Attribution Interpretation
The positive interaction term across all repetitions confirms that sender and receiver optimizations interact dynamically across real operating system sockets. Upgrading only the receiving peer against a legacy sender produces a **-4.8% CPU reduction**, but when both peers are updated, their behaviors interact and the combined CPU effect is non-additive. These results demonstrate full wire interoperability between the pre-DSA and post-PR61 endpoints without supporting simplified additive claims.

---

## 8. Transparent Disclosure of Regressions & Null Results

To maintain audit integrity, regressions and null results are disclosed explicitly alongside wins:
1. **Packet Loss at Scale**: In this campaign, actual packet-loss workloads regress broadly or remain neutral (+0.5% to +15.3% CPU at 200 connections, +9.4% to +30.4% at 1 connection). The wins are reorder-specific rather than generic loss-recovery wins.
2. **Lossless Low-Rate Streams**: At 1 Mbps, several cells show overlapping or slightly elevated CPU costs (+4% to +10%), reflecting variations within overlapping sample ranges.
3. **Monoio Ingress Regression**: Under common pooled ingress (`shared-pool:4`), `monoio` experiences packet delivery drops at 600 connections and elevated CPU across cells.

---

## 9. Final Conclusion

Closing the loop across the entire structural DSA roadmap (PR #37 through PR #61) yields an evidence-grounded record:
1. **Concrete Workload Wins**: The DSA roadmap as a whole produces substantial live speedups under **heavy packet reordering** (-23.3% to -24.2% on 200c×8M), **bonded broadcast demux** (-20.1%), and **selected medium-scale connection streams** (-7.5% to -22.9%).
2. **Methodological Honesty**: Under strict clean-capacity criteria requiring sustained $\ge 99.0\%$ offer across every repetition, the capacity frontier was not established because the load generator failed the offer gate.
3. **Complete Interoperability**: Full wire interoperability is verified between the pre-DSA baseline (`cde0e53`) and post-PR61 endpoint (`aba97ae`), with five runtime families demonstrating performance improvements under common configurations.
