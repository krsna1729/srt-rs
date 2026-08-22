#!/usr/bin/env bash
# Six-runtime SRT bake-off: for each backend, start a receiver and a sender
# with N connections at the default 8 Mbps/conn, then print both STATS lines.
#
# Usage: ./bakeoff.sh [N_CONNECTIONS] [SECONDS]
# Output: per-runtime STATS lines on stdout; raw process output in ./scratch/
set -euo pipefail

cd "$(dirname "$0")"

readonly BIN=./target/release/srt-bench
readonly SCRATCH_DIR=./scratch
readonly PORT_BASE=12000
readonly PORT_RANGE=1000
readonly LISTEN_HEAD_START_SECS=1

# Connections and seconds must be positive integers.
for arg in "$@"; do
  case $arg in
    ''|*[!0-9]*)
      echo "error: arguments must be positive integers (got '$arg')" >&2
      echo "usage: ${0##*/} [N_CONNECTIONS] [SECONDS]" >&2
      exit 2 ;;
  esac
done
readonly N_CONNECTIONS=${1:-300}
readonly SECONDS_PER_RUNTIME=${2:-8}

mkdir -p "$SCRATCH_DIR"

cleanup() {
  # Kill the backgrounded receiver if it outlived the sender (crash, signal).
  if [[ -n "${LISTENER_PID:-}" ]] && kill -0 "$LISTENER_PID" 2>/dev/null; then
    kill "$LISTENER_PID" 2>/dev/null || true
    wait "$LISTENER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

if [[ ! -x "$BIN" ]]; then
  echo "error: $BIN not found; build first:" >&2
  echo "  cargo build --release -p srt-bench" >&2
  exit 1
fi

for RUNTIME in mio tokio smol monoio glommio compio; do
  # Pick a free port by binding then releasing; closes the window where two
  # concurrent bake-offs would pick the same RANDOM value and clobber each
  # other's listeners mid-run.
  PORT=""
  for _ in $(seq 1 20); do
    CANDIDATE=$((PORT_BASE + RANDOM % PORT_RANGE))
    if ! (exec 3<>"/dev/udp/127.0.0.1/$CANDIDATE") 2>/dev/null; then
      continue
    fi
    exec 3>&- 3<&-
    if ! pgrep -f "srt-bench.*mode=receiver.*$CANDIDATE" >/dev/null 2>&1; then
      PORT=$CANDIDATE
      break
    fi
  done
  if [[ -z "$PORT" ]]; then
    echo "error: no free port found in [$PORT_BASE,$((PORT_BASE + PORT_RANGE)))" >&2
    exit 1
  fi

  LISTENER_OUT="$SCRATCH_DIR/bakeoff_${RUNTIME}_listener.out"
  CALLER_OUT="$SCRATCH_DIR/bakeoff_${RUNTIME}_caller.out"

  # shellcheck disable=SC2086  # intentional word split of arithmetic
  "$BIN" runtime="$RUNTIME" mode=receiver "$PORT" $((SECONDS_PER_RUNTIME + 5)) 120 \
    --connections "$N_CONNECTIONS" >"$LISTENER_OUT" 2>&1 &
  LISTENER_PID=$!

  sleep "$LISTEN_HEAD_START_SECS"

  set +e
  "$BIN" runtime="$RUNTIME" mode=sender 127.0.0.1 "$PORT" "$SECONDS_PER_RUNTIME" 120 \
    --connections "$N_CONNECTIONS" >"$CALLER_OUT" 2>&1
  CALLER_RC=$?
  set -e

  wait "$LISTENER_PID"
  LISTENER_PID=""

  grep STATS "$CALLER_OUT" | sed "s/^/[${RUNTIME} caller] /"
  grep STATS "$LISTENER_OUT" | sed "s/^/[${RUNTIME} listen] /"

  if [[ $CALLER_RC -ne 0 ]]; then
    echo "[${RUNTIME}] caller exited rc=$CALLER_RC (never connected?) — see $CALLER_OUT" >&2
  fi
done

echo BAKEOFF_DONE
