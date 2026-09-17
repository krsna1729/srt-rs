# Sustained-capacity surface (first gate-backed run)

Raw sweep output for `docs/results/sustained-capacity-qualification.md`, measured
with the bounded catch-up source (so `generated_ticks` reflects the offer, not the
service loop's punctuality) and judged by `cargo xtask qualify`.

```text
configuration        gate   f_drain  r_window  r_whole  WIN wire k/s  DATA k/s  p99 ms
F=50,   8 Mbps/dest  2/2      0.0%    1.224    1.224        46.5       38.0     5.3
F=100,  8 Mbps/dest  0/2     33-47%   0.867    1.455        65.9       76.0    28.3
F=100, 12 Mbps/dest  0/1     43.6%    0.745    1.507        84.4      113.2     5.4
F=150,  8 Mbps/dest  0/1     65.7%    0.535    1.569        61.0      114.0     7.4
F=200,  8 Mbps/dest  0/2     42.8%    0.342    1.546        51.9      152.0    40.6
F=200,  6 Mbps/dest  0/1     75.9%    0.306    1.424        34.8      113.7    65.7
F=200,  4 Mbps/dest  0/1     70.5%    0.584    1.980        44.3       76.0    12.6
F=200,  2 Mbps/dest  0/1     44.4%    1.092    1.964        41.5       38.0    16.8
```

**A row is only sustained if the work happens inside the source window.** That is
what `f_drain` measures: the share of wire datagrams submitted *after* the source
stopped. Exactly one configuration in this surface keeps pace -- **F=50 at
8 Mbps, `f_drain = 0.0 %`, `r_window = r_whole = 1.224`**. Every other row
accepted more than it could transmit and emptied the difference during a drain
that cost 3.2-10.0 s of CPU, so those rows establish *admission plus eventual
delivery*, not sustainable service.

**`WIN wire k/s` is the in-window rate** (`tx_submitted_wire / window`), and it is
the only rate comparable to an offered rate. It spans 34.8-84.4 K datagrams/s and
does **not** rise with the offer: the shard's in-window submission rate is set by
its service rate, so a higher offer does not produce a higher sustained wire rate
-- it produces a larger backlog.

**Two `r`s, two jobs.** `r_window = tx_submitted_wire / (generated_ticks x F)` is
the wire cost of the DATA actually offered during the window and is the one that
describes sustainable service; `r_whole = (tx_submitted_wire + drain_submitted) /
rx_core_total` is whole-work accounting and must never be multiplied by a DATA
rate to produce an instantaneous figure. `r_window < 1` is the backlog signature
-- fewer wire datagrams left the shard than DATA arrived -- and `r_window = 1.22`
at F=50 matches the draft's ~0.28 control budget for a shard that keeps up.

`r` is `(tx_submitted_wire + drain_submitted) / rx_core_total`; `C_SRT` is
`(window_cpu_ms + drain_cpu_ms) * 1000 / rx_core_total`.

One repetition per configuration except `F=50, 8` and `F=100, 8` and `F=200, 8`,
which have two. The protocol asks for three or more; this is a first surface, not
the final qualification.
