#!/usr/bin/env bash
# mio-only connection-count sweep: runs one receiver/sender pair per count to
# locate the scaling knee where the flat epoll loop's line-rate advantage
# kicks in.
#
# Usage: ./knee-sweep.sh N [N...]
# Output: per-N STATS lines on stdout; raw process output in ./scratch/
set -euo pipefail

cd "$(dirname "$0")"

readonly BIN=./target/release/srt-bench
readonly SCRATCH_DIR=./scratch
readonly PORT_BASE=9700
readonly LISTEN_HEAD_START_SECS=2
readonly RECEIVER_SECS=15
readonly SENDER_SECS=8
readonly LATENCY_MS=120

mkdir -p "$SCRATCH_DIR"

cleanup() {
  if [[ -n "${LISTENER_PID:-}" ]] && kill -0 "$LISTENER_PID" 2>/dev/null; then
    kill "$LISTENER_PID" 2>/dev/null || true
    wait "$LISTENER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

if [[ $# -lt 1 ]]; then
  echo "usage: ${0##*/} N_CONNECTIONS [N_CONNECTIONS...]" >&2
  exit 2
fi

for arg in "$@"; do
  case $arg in
    ''|*[!0-9]*|0)
      echo "error: connection counts must be positive integers (got '$arg')" >&2
      exit 2 ;;
  esac
done

if [[ ! -x "$BIN" ]]; then
  echo "error: $BIN not found; building..." >&2
  RUSTFLAGS="" cargo build -p srt-bench --release --bin srt-bench \
    >"$SCRATCH_DIR/knee_sweep_build.log" 2>&1 || {
      echo "BUILD_FAIL — see $SCRATCH_DIR/knee_sweep_build.log" >&2
      tail -5 "$SCRATCH_DIR/knee_sweep_build.log" >&2
      exit 1
    }
fi

for N in "$@"; do
  PORT=$((PORT_BASE + N))
  LISTENER_OUT="$SCRATCH_DIR/knee_sweep_${N}_listener.out"
  CALLER_OUT="$SCRATCH_DIR/knee_sweep_${N}_caller.out"

  echo "=== N=$N port=$PORT ==="

  # shellcheck disable=SC2086  # intentional word split of arithmetic
  "$BIN" runtime=mio mode=receiver "$PORT" "$RECEIVER_SECS" "$LATENCY_MS" \
    --connections "$N" >"$LISTENER_OUT" 2>&1 &
  LISTENER_PID=$!

  sleep "$LISTEN_HEAD_START_SECS"

  set +e
  "$BIN" runtime=mio mode=sender 127.0.0.1 "$PORT" "$SENDER_SECS" "$LATENCY_MS" \
    --connections "$N" >"$CALLER_OUT" 2>&1
  CALLER_RC=$?
  set -e

  wait "$LISTENER_PID"
  LISTENER_PID=""

  grep STATS "$CALLER_OUT" | sed "s/^/[mio caller] /"
  grep STATS "$LISTENER_OUT" | sed "s/^/[mio listen] /"

  if [[ $CALLER_RC -ne 0 ]]; then
    echo "[N=$N] caller exited rc=$CALLER_RC (never connected?) — see $CALLER_OUT" >&2
  fi
done

echo KNEESWEEP_DONE
