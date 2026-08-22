#!/usr/bin/env bash
set -u
cd "$(dirname "$0")"
BIN=./target/release/srt-bench
N=${1:-300}
T=${2:-8}
for R in mio tokio smol monoio glommio compio; do
  P=$((12000 + RANDOM % 1000))
  "$BIN" runtime="$R" mode=receiver "$P" $((T+5)) 120 --connections "$N" >"/tmp/bk_${R}_l.out" 2>&1 &
  LP=$!
  sleep 1
  "$BIN" runtime="$R" mode=sender 127.0.0.1 "$P" "$T" 120 --connections "$N" >"/tmp/bk_${R}_c.out" 2>&1
  wait "$LP"
  grep STATS "/tmp/bk_${R}_c.out" | sed "s/^/[${R} caller] /"
  grep STATS "/tmp/bk_${R}_l.out" | sed "s/^/[${R} listen] /"
done
echo BAKEOFF_DONE
