#!/usr/bin/env bash
# Scaling sweep driver: S concurrent sender shards against S receiver
# processes, one destination per UDP port.
#
# This is the driver for docs/results/scaling-to-1000.md. It exists because
# the claim under test is about *concurrent* shards: running the shards
# sequentially, or sharing one receiver process across them, would measure a
# different (and much easier) system than the one being claimed.
#
# Usage:
#   scaling-sweep.sh <out.tsv> <N> <S> <reps> [window_ms] [K] [H] [base_port]
#
#   N   total destinations          (must divide by S)
#   S   concurrent sender shards    (one receiver process each)
#   K   TX lanes per shard          (fixed cost model; default 256)
#   H   connect concurrency         (default 64)
#
# Per rep it starts S receivers (each owning N/S consecutive ports), then S
# sender processes concurrently, waits for all of them, and appends:
#   one ROW line per shard, then one AGG line summing the shards.
#
# Nothing here is shared between shards: separate processes, separate
# sockets, disjoint port ranges. If a shard count is only reachable by
# sharing state, this driver cannot express it -- deliberately.
set -u -o pipefail

OUT=${1:?usage: scaling-sweep.sh <out.tsv> <N> <S> <reps> [window_ms] [K] [H] [base_port]}
N=${2:?N}
S=${3:?S}
REPS=${4:?reps}
WINDOW_MS=${5:-3000}
K=${6:-256}
H=${7:-64}
BASE=${8:-30000}
PAYLOAD=${9:-1316}

if [ $((N % S)) -ne 0 ]; then echo "N must divide by S" >&2; exit 2; fi
F=$((N / S))

ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
BENCH=$(ls -t "$ROOT"/target/release/deps/compio_shared_owner_qual-* 2>/dev/null | grep -v '\.d$' | head -1)
RECV="$ROOT/target/release/srt-bench"
[ -x "$BENCH" ] || { echo "build first: cargo build --release -p srt-bench --bench compio_shared_owner_qual" >&2; exit 2; }
[ -x "$RECV" ] || { echo "build first: cargo build --release -p srt-bench" >&2; exit 2; }

WORK=$(mktemp -d)
cleanup() { kill $(jobs -p) 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT

echo -e "# scaling-sweep N=$N S=$S F=$F K=$K H=$H window_ms=$WINDOW_MS reps=$REPS base_port=$BASE payload_bytes=$PAYLOAD git_sha=$(cd "$ROOT" && git rev-parse --short HEAD) git_dirty=$(cd "$ROOT" && { git diff --quiet && echo false || echo true; })" > "$OUT"
# Header is generated from the same key lists the rows are built from, so a
# column can never drift out of alignment with its label again.
python3 - "$OUT" <<'PY'
import sys
tx_keys = """established expected_ticks generated_ticks missed_source_ticks data_offered
data_accepted tx_submitted_wire tx_completed drain_submitted drain_completed drain_ok
pending_after_drain inflight_at_window_end service_visits lateness_us_p50 p99 max
window_cpu_ms drain_cpu_ms cpu_ms rx_mode managed_rx rx_dropped rx_truncated
tx_pool_free tx_pool_capacity payload_bytes interval_us""".split()
rx_keys = """connections established pkt_sent core_total sec_a rtt_ms elapsed_s cpu_user_ms
cpu_sys_ms data_min data_p50 data_max data_zero data_below_half_mean""".split()
hdr = ['kind', 'rep', 'shard', 'fanout'] + tx_keys + ['rx_' + k for k in rx_keys]
open(sys.argv[1], 'a').write('\t'.join(hdr) + '\n')
PY

for rep in $(seq 1 "$REPS"); do
  # Distinct port region per rep so a stuck socket from the previous rep
  # cannot be mistaken for a fresh destination.
  RBASE=$((BASE + rep * 2000))
  for s in $(seq 0 $((S - 1))); do
    port=$((RBASE + s * F))
    # The receiver must outlive connect + window + the post-window drain.
    # At 12 s it did not: the senders were still draining when the receiver
    # exited, so the drain's datagrams were sent to a closed socket and the
    # published `core_total` covered the window only. Window-phase
    # reconciliation looked exact either way, which is exactly why the
    # lifetime has to be derived from the window rather than guessed.
    rx_secs=$((WINDOW_MS / 1000 + 30))
    "$RECV" runtime=compio mode=receiver "$port" "$rx_secs" 120 --connections "$F" \
      > "$WORK/rx.$s.log" 2>&1 &
  done
  sleep 1
  for s in $(seq 0 $((S - 1))); do
    port=$((RBASE + s * F))
    "$BENCH" --fanout "$F" --duration-ms "$WINDOW_MS" --base-port "$port" \
      --tx-lanes "$K" --connect-cc "$H" --payload-bytes "$PAYLOAD" > "$WORK/tx.$s.log" 2>&1 &
  done
  # Wait for the sender shards only; the receivers keep reading through the
  # drain and stop at their own deadline.
  for s in $(seq 0 $((S - 1))); do
    port=$((RBASE + s * F))
    while pgrep -f "compio_shared_owner_qual.*--base-port $port" > /dev/null; do sleep 1; done
  done
  sleep 12
  kill $(jobs -p) 2>/dev/null
  sleep 1

  for s in $(seq 0 $((S - 1))); do
    python3 - "$OUT" "$rep" "$s" "$WORK/tx.$s.log" "$WORK/rx.$s.log" <<'PY'
import re, sys
out, rep, shard, txlog, rxlog = sys.argv[1:6]
def kv(line):
    d = {}
    for tok in line.split():
        if '=' in tok:
            k, v = tok.split('=', 1)
            d[k] = v
    return d
tx = next((kv(l) for l in open(txlog) if l.startswith('SHARED_OWNER_QUAL')), {})
rx_line = next((l for l in open(rxlog) if l.startswith('STATS')), '')
rx = kv(rx_line)
tx_keys = """established expected_ticks generated_ticks missed_source_ticks data_offered
data_accepted tx_submitted_wire tx_completed drain_submitted drain_completed drain_ok
pending_after_drain inflight_at_window_end service_visits lateness_us_p50 p99 max
window_cpu_ms drain_cpu_ms cpu_ms rx_mode managed_rx rx_dropped rx_truncated
tx_pool_free tx_pool_capacity payload_bytes interval_us""".split()
rx_keys = """connections established pkt_sent core_total sec_a rtt_ms elapsed_s cpu_user_ms
cpu_sys_ms data_min data_p50 data_max data_zero data_below_half_mean""".split()
row = ['ROW', rep, shard, tx.get('fanout', '?')]
row += [tx.get(k, '') for k in tx_keys]
row += [rx.get(k, '') for k in rx_keys]
print('\t'.join(row))
PY
  done >> "$OUT"
done

# Aggregate the last rep's per-shard rows so a partially failed sweep is visible.
python3 - "$OUT" <<'PY'
import sys
path = sys.argv[1]
rows = [l.rstrip('\n').split('\t') for l in open(path) if l.startswith('ROW\t')]
if not rows: sys.exit(0)
hdr = [l for l in open(path) if l.startswith('kind\t')][0].rstrip('\n').split('\t')
last_rep = rows[-1][1]
sel = [r for r in rows if r[1] == last_rep]
sum_keys = {'data_offered','data_accepted','tx_submitted_wire','tx_completed','drain_submitted',
            'drain_completed','expected_ticks','generated_ticks','missed_source_ticks',
            'service_visits','rx_core_total','rx_data_min','rx_data_zero','rx_data_below_half',
            'rx_established','rx_connections'}
tl = hdr.index('lateness_us_p50'); p99 = hdr.index('p99'); mx = hdr.index('max')
tot = {k: 0.0 for k in sum_keys}
for r in sel:
    for k in sum_keys:
        v = r[hdr.index(k)]
        try: tot[k] += float(v)
        except ValueError: pass
def g(k, default=''):
    v = tot[k]
    return str(int(v)) if v == int(v) else f'{v:.1f}'
agg = ['AGG', last_rep, str(len(sel)), ''] + [''] * (len(hdr) - 4)
def put(k, val): agg[hdr.index(k)] = val
for k in sum_keys: put(k, g(k))
put('lateness_us_p50', max(r[tl] for r in sel))
put('p99', max(r[p99] for r in sel))
put('max', max(r[mx] for r in sel))
print('\t'.join(agg), file=open(path, 'a'))
PY
echo "wrote $OUT"
