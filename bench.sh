#!/usr/bin/env bash
# Unified SRT benchmark harness. One tool, three modes:
#
#   ./bench.sh bakeoff [N] [SECONDS]        all six runtimes at one density
#   ./bench.sh knee N [N...]                all six runtimes swept over N
#   ./bench.sh baseline [N] [SECONDS]       all six runtimes, REPS reps,
#                                           median table (same-window rule)
#   ./bench.sh sysprof RUNTIME [N] [SECS]   perf-tracepoint attribution for
#                                           one runtime: socket syscalls +
#                                           io_uring SQEs per 10k packets
#
# Common knobs via env:
#   REPS=3      repetitions for baseline mode (>=3 per method rules)
#   TAG=name    output file prefix tag for baseline mode
#
# Every mode is symmetric: all six runtimes (mio tokio smol monoio glommio
# compio) get identical treatment. Each run: receiver/sender pair on port+i
# per connection, one STATS line each in ./scratch/, STATS echoed to stdout.
#
set -euo pipefail

cd "$(dirname "$0")"

readonly BIN=./target/release/srt-bench
readonly SCRATCH_DIR=./scratch
readonly RUNTIMES=(mio tokio smol monoio glommio compio)

readonly LATENCY_MS=120

LISTENER_PID=""

cleanup() {
  if [[ -n "$LISTENER_PID" ]] && kill -0 "$LISTENER_PID" 2>/dev/null; then
    kill "$LISTENER_PID" 2>/dev/null || true
    wait "$LISTENER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

usage() {
  cat >&2 <<'EOF'
usage: bench.sh bakeoff [N_CONNECTIONS] [SECONDS]
       bench.sh knee N_CONNECTIONS [N_CONNECTIONS...]
       bench.sh baseline [N_CONNECTIONS] [SECONDS]
env:   REPS=3 (baseline reps), TAG=name (output prefix)
EOF
  exit 2
}

require_positive_int() {
  local name=$1 value=$2
  case $value in
    ''|*[!0-9]*|0)
      echo "error: $name must be a positive integer (got '$value')" >&2
      usage ;;
  esac
}

ensure_binary() {
  if [[ ! -x "$BIN" ]]; then
    echo "info: $BIN not found; building..." >&2
    mkdir -p "$SCRATCH_DIR"
    RUSTFLAGS="" cargo build -p srt-bench --release --bin srt-bench \
      >"$SCRATCH_DIR/build.log" 2>&1 || {
        echo "BUILD_FAIL — see $SCRATCH_DIR/build.log" >&2
        tail -5 "$SCRATCH_DIR/build.log" >&2
        exit 1
      }
  fi
}

# Pick a free UDP port by binding then releasing; pgrep cross-check closes
# the race against another concurrently-starting harness.
pick_port() {
  local base=$1 range=$2 candidate i
  for i in $(seq 1 20); do
    candidate=$((base + RANDOM % range))
    if ! (exec 3<>"/dev/udp/127.0.0.1/$candidate") 2>/dev/null; then
      continue
    fi
    exec 3>&- 3<&-
    if ! pgrep -f "srt-bench.*mode=receiver.*$candidate" >/dev/null 2>&1; then
      printf '%s' "$candidate"
      return 0
    fi
  done
  return 1
}

# run_pair RUNTIME PORT N SECONDS HEAD_START OUT_PREFIX
# Spawns receiver+sender for one cell; echoes both STATS lines to stdout.
#
# Env knobs (both apply to receiver AND sender -- the sender needs to know
# the ingress topology too, since a pooled sender dials the single shared
# port instead of one port per connection):
#   INGRESS=pool=K    multi-acceptor SO_REUSEPORT listener, K threads
#   BOND_GROUPS=G     connections 2g/2g+1 share a bond group, for g in 0..G
run_pair() {
  local runtime=$1 port=$2 n=$3 secs=$4 head_start=$5 out=$6
  LISTENER_OUT="$SCRATCH_DIR/${out}_listener.out"
  CALLER_OUT="$SCRATCH_DIR/${out}_caller.out"

  local extra_args=()
  if [[ -n "${INGRESS:-}" ]]; then
    extra_args+=(--ingress="$INGRESS")
  fi
  if [[ -n "${BOND_GROUPS:-}" ]]; then
    extra_args+=(--bond-groups="$BOND_GROUPS")
  fi

  # shellcheck disable=SC2086  # intentional word split of arithmetic
  "$BIN" runtime="$runtime" mode=receiver "$port" $((secs + 5)) "$LATENCY_MS" \
    --connections "$n" "${extra_args[@]}" >"$LISTENER_OUT" 2>&1 &
  LISTENER_PID=$!

  sleep "$head_start"

  set +e
  "$BIN" runtime="$runtime" mode=sender 127.0.0.1 "$port" "$secs" "$LATENCY_MS" \
    --connections "$n" "${extra_args[@]}" >"$CALLER_OUT" 2>&1
  CALLER_RC=$?
  set -e

  wait "$LISTENER_PID"
  LISTENER_PID=""

  grep STATS "$CALLER_OUT" | sed "s/^/[${runtime} caller] /"
  grep STATS "$LISTENER_OUT" | sed "s/^/[${runtime} listen] /"

  if [[ $CALLER_RC -ne 0 ]]; then
    echo "[${runtime}] caller exited rc=$CALLER_RC (never connected?) — see $CALLER_OUT" >&2
  fi
}

mode_bakeoff() {
  local n=${1:-300} secs=${2:-8}
  require_positive_int N "$n"
  require_positive_int SECONDS "$secs"
  ensure_binary
  for runtime in "${RUNTIMES[@]}"; do
    local port
    port=$(pick_port 12000 1000) || { echo "error: no free port" >&2; exit 1; }
    run_pair "$runtime" "$port" "$n" "$secs" 1 "bakeoff_${runtime}"
  done
  echo BAKEOFF_DONE
}

mode_knee() {
  [[ $# -ge 1 ]] || usage
  local n
  for n in "$@"; do require_positive_int CONNECTIONS "$n"; done
  ensure_binary
  for n in "$@"; do
    echo "=== N=$n ==="
    for runtime in "${RUNTIMES[@]}"; do
      local port
      # Deterministic port per (N, runtime) keeps repeat sweeps comparable.
      port=$(pick_port $((9700 + n)) 50) || { echo "error: no free port" >&2; exit 1; }
      run_pair "$runtime" "$port" "$n" 8 2 "knee_sweep_${runtime}_${n}"
    done
  done
  echo KNEESWEEP_DONE
}

# Aggregate the STATS lines this run just wrote into a median table.
print_medians() {
  local tag=$1 reps=$2 n=$3 secs=$4
  python3 - "$SCRATCH_DIR" "$tag" "$reps" "$n" "$secs" "${RUNTIMES[@]}" <<'PYEOF'
import re, sys, statistics
scratch, tag, reps, n, secs = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5]
runtimes = sys.argv[6:]
pat = re.compile(r"STATS role=(\w+) backend=\w+ connections=\d+ pkt_sent=(\d+) "
                 r"core_total=(\d+) sec_a=(\d+) sec_b=(\d+) rtt_ms=([\d.]+) "
                 r"elapsed_s=([\d.]+) throughput_pps=[\d.]+ cpu_user_ms=([\d.]+) "
                 r"cpu_sys_ms=([\d.]+) peak_rss_kb=(\d+)")
print(f"=== medians over {reps} reps, N={n}, T={secs}s ===")
print(f"{'runtime':8s} {'sent':>12s} {'recv':>12s} {'retx':>10s} {'loss':>10s} "
      f"{'rtt_ms':>9s} {'cpu_s':>9s} {'rss_kb':>9s}")
for rt in runtimes:
    rows = []
    for rep in range(1, reps + 1):
        c = l = None
        for side in ("caller", "listener"):
            try:
                txt = open(f"{scratch}/{tag}_{rt}_r{rep}_{side}.out").read()
            except FileNotFoundError:
                continue
            m = pat.search(txt)
            if not m:
                continue
            role, sent, total, sec_a, sec_b, rtt, _, uu, us, rss = m.groups()
            d = dict(sent=int(sent), total=int(total), sec_a=int(sec_a),
                     sec_b=int(sec_b), rtt=float(rtt), uu=float(uu), us=float(us),
                     rss=int(rss))
            if role == "caller":
                c = d
            else:
                l = d
        if c and l:
            rows.append((c["sent"], l["total"], c["sec_a"] + l["sec_a"], l["sec_b"],
                         l["rtt"],
                         (c["uu"] + c["us"] + l["uu"] + l["us"]) / 1000,
                         max(c["rss"], l["rss"])))
    if rows:
        med = lambda i: statistics.median(r[i] for r in rows)
        print(f"{rt:8s} {med(0):12.0f} {med(1):12.0f} {med(2):10.0f} {med(3):10.0f} "
              f"{med(4):9.2f} {med(5):9.1f} {med(6):9.0f}")
    else:
        print(f"{rt:8s} {'NO-DATA':>12s}")
PYEOF
}

mode_baseline() {
  local n=${1:-300} secs=${2:-8} tag=${TAG:-baseline}
  require_positive_int N "$n"
  require_positive_int SECONDS "$secs"
  local reps=${REPS:-3}
  require_positive_int REPS "$reps"
  ensure_binary
  for rep in $(seq 1 "$reps"); do
    for runtime in "${RUNTIMES[@]}"; do
      local port
      port=$(pick_port 21000 4000) || { echo "error: no free port" >&2; exit 1; }
      run_pair "$runtime" "$port" "$n" "$secs" 1 "${tag}_${runtime}_r${rep}" >/dev/null
    done
  done
  print_medians "$tag" "$reps" "$n" "$secs"
}

mode_sysprof() {
  local runtime=${1:?runtime required}
  local n=${2:-300} secs=${3:-8} tag=${TAG:-sysprof}
  case "$runtime" in mio|tokio|smol|monoio|glommio|compio) ;;
    *) echo "error: unknown runtime '$runtime'" >&2; usage ;;
  esac
  require_positive_int N "$n"
  require_positive_int SECS "$secs"
  ensure_binary

  # Socket syscalls cover the readiness backends; io_uring backends never
  # issue socket syscalls -- every op is a submission queue entry, so the
  # SQE tracepoint is what makes them visible at all.
  readonly EVENTS="syscalls:sys_enter_recvfrom,syscalls:sys_enter_sendto,\
syscalls:sys_enter_sendmsg,syscalls:sys_enter_recvmsg,\
syscalls:sys_enter_epoll_wait,io_uring:io_uring_submit_req"

  local port
  port=$(pick_port 25000 2000) || { echo "error: no free port" >&2; exit 1; }
  local lp_out="$SCRATCH_DIR/${tag}_${runtime}_listener"
  local cp_out="$SCRATCH_DIR/${tag}_${runtime}_caller"
  rm -f "$lp_out.out" "$lp_out.perf" "$cp_out.out" "$cp_out.perf"

  perf stat -e "$EVENTS" -x, -o "$lp_out.perf" \
    "$BIN" runtime="$runtime" mode=receiver "$port" $((secs + 5)) "$LATENCY_MS" \
    --connections "$n" >"$lp_out.out" 2>&1 &
  LISTENER_PID=$!
  sleep 1
  perf stat -e "$EVENTS" -x, -o "$cp_out.perf" \
    "$BIN" runtime="$runtime" mode=sender 127.0.0.1 "$port" "$secs" "$LATENCY_MS" \
    --connections "$n" >"$cp_out.out" 2>&1 || true
  wait "$LISTENER_PID"
  LISTENER_PID=""

  python3 - "$tag" "$runtime" "$SCRATCH_DIR" <<'PYEOF'
import sys, re

tag, runtime, scratch = sys.argv[1], sys.argv[2], sys.argv[3]

def load(side):
    counts = {}
    with open(f"{scratch}/{tag}_{runtime}_{side}.perf") as f:
        for line in f:
            parts = line.strip().split(",")
            if len(parts) >= 3 and ":" in parts[2]:
                counts[parts[2].split(":", 1)[1]] = int(float(parts[0]))
    stats = {}
    m = re.search(r"STATS .*", open(f"{scratch}/{tag}_{runtime}_{side}.out").read())
    if m:
        for kv in m.group(0).split()[1:]:
            k, _, v = kv.partition("=")
            stats[k] = v
    return counts, stats

print(f"=== syscall attribution: {runtime} ===")
for side, label in (("caller", "caller"), ("listener", "listener")):
    counts, st = load(side)
    pkts = int(st.get("core_total", 0)) or int(st.get("pkt_sent", 0))
    cpu_user = float(st.get("cpu_user_ms", 0))
    cpu_sys = float(st.get("cpu_sys_ms", 0))
    rx = counts.get("sys_enter_recvfrom", 0) + counts.get("sys_enter_recvmsg", 0)
    tx = counts.get("sys_enter_sendto", 0) + counts.get("sys_enter_sendmsg", 0)
    ep = counts.get("sys_enter_epoll_wait", 0)
    sqe = counts.get("io_uring_submit_req", 0)
    total_ops = rx + tx + ep + sqe
    print(f"{label:9s} pkts={pkts:>9d} rx={rx:>9d} tx={tx:>9d} epoll={ep:>9d} "
          f"io_sqe={sqe:>9d} | cpu_user={cpu_user:>8.0f}ms cpu_sys={cpu_sys:>8.0f}ms")
    if pkts:
        k = 10000.0 / pkts
        print(f"{'':9s} ops-per-10k-pkt: rx={k*rx:8.1f} tx={k*tx:8.1f} "
              f"epoll={k*ep:8.1f} sqe={k*sqe:8.1f} total={k*total_ops:8.1f}")
PYEOF
}

mkdir -p "$SCRATCH_DIR"
MODE=${1:-}
shift || true
case $MODE in
  bakeoff)  mode_bakeoff "$@" ;;
  knee)     mode_knee "$@" ;;
  baseline) mode_baseline "$@" ;;
  sysprof)  mode_sysprof "$@" ;;
  *)        usage ;;
esac
