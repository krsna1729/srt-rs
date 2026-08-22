#!/usr/bin/env bash
set -u
cd "$(dirname "$0")"
BIN=./target/release/srt-bench
RUSTFLAGS="" cargo build -p srt-bench --release --bin srt-bench >/tmp/kneesweep_build.log 2>&1 || { echo BUILD_FAIL; tail -5 /tmp/kneesweep_build.log; exit 1; }
for N in "$@"; do
  P=$((9700 + N))
  echo "=== N=$N port=$P ==="
  "$BIN" runtime=mio mode=receiver "$P" 15 120 --connections "$N" >"/tmp/knee_${N}_l.out" 2>&1 &
  LP=$!
  sleep 2
  "$BIN" runtime=mio mode=sender 127.0.0.1 "$P" 8 120 --connections "$N" >"/tmp/knee_${N}_c.out" 2>&1
  wait "$LP"
  grep STATS "/tmp/knee_${N}_c.out" | sed "s/^/[mio caller] /"
  grep STATS "/tmp/knee_${N}_l.out" | sed "s/^/[mio listen] /"
done
echo KNEESWEEP_DONE
