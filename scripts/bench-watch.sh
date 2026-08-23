#!/usr/bin/env bash
# Live system watch for a running benchmark sweep.
#
# Prints one line per *anomaly* rather than a continuous feed, so it can be
# tailed (or piped into a notifier) without drowning the run it is watching.
# A periodic heartbeat proves it is still alive and gives an htop-style
# snapshot of where the time and memory are going.
#
#   scripts/bench-watch.sh [interval_secs] [heartbeat_every_n_samples]
#
# What it watches, and why each one matters here:
#   loadavg      - a sweep that saturates the box is measuring the box
#   MemAvailable - the pathology this project already hit once was RSS
#   swap         - any swapping invalidates every latency number
#   UDP drops    - rcvbuf overflow is silent loss: the protocol sees no
#                  gap, so it never retransmits and the result just looks
#                  like a slow listener
set -u
interval="${1:-5}"
beat_every="${2:-12}"
cores=$(nproc)

read_udp() {  # -> "rcvbuf in_err no_ports"
  awk '/^Udp:/ { if (h=="") { for (i=1;i<=NF;i++) n[$i]=i; h=1; next }
                 print $(n["RcvbufErrors"]), $(n["InErrors"]), $(n["NoPorts"]) }' /proc/net/snmp
}

# Swap already in use before the sweep started is the host's business,
# not this run's; only growth from here is a finding.
sw_base=$(awk '/^SwapTotal:/{t=$2} /^SwapFree:/{f=$2} END{print int((t-f)/1024)}' /proc/meminfo)
prev=($(read_udp)); i=0
printf 'watching: %s cores, interval %ss\n' "$cores" "$interval"
while :; do
  sleep "$interval"; i=$((i+1))
  cur=($(read_udp))
  d_rcv=$(( ${cur[0]} - ${prev[0]} )); d_err=$(( ${cur[1]} - ${prev[1]} ))
  d_np=$(( ${cur[2]} - ${prev[2]} )); prev=("${cur[@]}")

  load=$(cut -d' ' -f1 /proc/loadavg)
  mem_av=$(awk '/^MemAvailable:/{print int($2/1024)}' /proc/meminfo)
  mem_tot=$(awk '/^MemTotal:/{print int($2/1024)}' /proc/meminfo)
  sw_tot=$(awk '/^SwapTotal:/{print int($2/1024)}' /proc/meminfo)
  sw_free=$(awk '/^SwapFree:/{print int($2/1024)}' /proc/meminfo)
  sw_used=$(( sw_tot - sw_free ))
  sw_grown=$(( sw_used - sw_base ))
  # Exclude ps itself: it is always the busiest thing in its own output.
  top=$(ps -eo pcpu,rss,comm --sort=-pcpu --no-headers 2>/dev/null |
        awk '$3 != "ps" {printf "%s(%.0f%% %dMB) ", $3, $1, $2/1024; if (++n==3) exit}')

  # Anomalies, loudest first.
  (( d_rcv > 1000 )) && printf 'ANOMALY udp-rcvbuf-drops %s in %ss (silent loss: no NAK will follow) | %s\n' "$d_rcv" "$interval" "$top"
  (( d_err > 1000 )) && printf 'ANOMALY udp-in-errors %s in %ss | %s\n' "$d_err" "$interval" "$top"
  (( d_np  > 1000 )) && printf 'ANOMALY udp-no-ports %s in %ss (sending to a closed port) | %s\n' "$d_np" "$interval" "$top"
  (( sw_grown > 64 )) && printf 'ANOMALY swap-grew %sMB since start, %sMB total (every latency number is now suspect) | %s\n' "$sw_grown" "$sw_used" "$top"
  (( mem_av * 10 < mem_tot )) && printf 'ANOMALY mem-available %sMB of %sMB | %s\n' "$mem_av" "$mem_tot" "$top"
  awk -v l="$load" -v c="$cores" 'BEGIN{exit !(l > c*1.5)}' &&
    printf 'ANOMALY load %s on %s cores | %s\n' "$load" "$cores" "$top"

  if (( i % beat_every == 0 )); then
    printf 'beat load=%s mem_avail=%sMB swap+%sMB udp_drops/%ss=%s | %s\n' \
      "$load" "$mem_av" "$sw_grown" "$interval" "$d_rcv" "$top"
  fi
done
