#!/usr/bin/env bash
# Convert an srt-bench matrix TSV into the JSON array
# benchmark-action/github-action-benchmark's `customBiggerIsBetter` tool
# expects, for the GitHub Pages trend chart.
#
# One series per runtime: aggregate delivered-packet throughput
# (sum(pkt_sent)/sum(elapsed_s) across every listener-role row for that
# runtime), not a per-cell breakdown. A different plan/connection-count/
# encryption mix runs on different days (nightly vs weekly, and the plans
# each covers), so per-cell series would be mostly-empty most days;
# per-runtime is the one grouping that's always populated and always
# comparable across runs. listener (not caller) rows: pkt_sent there
# reflects packets actually delivered, not just offered.
#
#   scripts/bench-tsv-to-benchmark-json.sh results.tsv > benchmark.json
set -euo pipefail

tsv="${1:?usage: bench-tsv-to-benchmark-json.sh results.tsv}"

awk -F'\t' '
  NR==1 {
    for (i=1;i<=NF;i++) h[$i]=i
    next
  }
  $(h["role"])=="listener" {
    rt=$(h["runtime"])
    if (!(rt in seen)) { order[n++]=rt; seen[rt]=1 }
    sent[rt]+=$(h["pkt_sent"])
    secs[rt]+=$(h["elapsed_s"])
  }
  END {
    printf "["
    emitted=0
    for (i=0;i<n;i++) {
      rt=order[i]
      if (secs[rt] > 0) {
        val = sent[rt]/secs[rt]
        if (emitted>0) printf ","
        printf "\n  {\"name\": \"%s\", \"unit\": \"pkt/s\", \"value\": %.1f}", rt, val
        emitted++
      }
    }
    printf "\n]\n"
  }
' "$tsv"
