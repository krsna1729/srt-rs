# Two-process Compio qualification frontier (dc83aa2)

Host: Ubuntu 6.8.0-139-generic, AMD EPYC (KVM), 6 CPUs, 11 GB RAM.
Source: 8 Mbps open-loop, 1316B payloads, plaintext, per-connection egress.
Harness: `srt-bench runtime=compio mode=sender|receiver` (task-per-connection
bench adapter, NOT the shared Owner datapath — sender/receiver roles only).

## fanout 100 (clean)

| side | established | pkt_sent | core_total | throughput_pps | cpu_user_ms | cpu_sys_ms | peak_rss_kb |
|------|-------------|----------|------------|----------------|-------------|------------|-------------|
| sender | 100/100 | 3029243 | 3029243 | 55739 | 21271.5 | 28340.4 | 19016 |
| receiver | 100/100 | 3029239 | 3029239 | 52773 | 18700.0 | 24867.1 | 37984 |

Delivery: sender core_total == receiver core_total within 4 packets
(3029243 vs 3029239). Drain: both sides exit 0; receiver STATS shows
torn_down=0. Latency (rtt_ms): sender 0.000 (sender-side clock), receiver
24.805. Raw TSVs: `qual-compio-100-send.tsv`, `qual-compio-100-recv.tsv`.

## fanout 600 (partial: 364/600 established)

| side | established | pkt_sent | core_total | throughput_pps | cpu_user_ms | cpu_sys_ms | peak_rss_kb |
|------|-------------|----------|------------|----------------|-------------|------------|-------------|
| sender | 364/600 | 3800522 | 3800522 | 34543 | 49428.1 | 59217.9 | 38216 |
| receiver | 364/600 | 3800375 | 3800375 | 33033 | 44675.0 | 60502.1 | 50036 |

Handshake timeout on 236 legs (`connect timed out, state=Listening`);
established legs deliver symmetric packet counts (3800522 vs 3800375,
delta 147 = in-flight at shutdown). Receiver torn_down=19 at exit.
Raw TSVs: `qual-compio-600-send.tsv`, `qual-compio-600-recv.tsv`.

## Interpretation

- The task-per-connection bench adapter sustains 100 destinations cleanly
  on this host; 600 exceeds single-process handshake throughput (not an
  Owner datapath result — the shared Owner was not under test here).
- Shard frontier on this host: 1 process x 100 destinations clean;
  600 needs sharding and/or connect-concurrency tuning.
- Next: run the shared-Owner two-process harness (Owner sender shards x
  external receiver) to measure Q << F with the real datapath.
