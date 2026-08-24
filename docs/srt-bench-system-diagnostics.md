# srt-bench host-capacity diagnostics

`srt-bench` raises its soft `RLIMIT_NOFILE` to the process hard limit before
dispatching either a direct runtime or a matrix. Matrix children inherit that
limit. It cannot raise the hard limit; if the hard limit is too small, the
launcher or service that starts the benchmark must raise it first.

Run the diagnostic directly with:

```sh
target/release/srt-bench system-info
```

`srt-bench matrix` prints the same key/value report once before expanding the
cells. The report includes:

- soft and hard open-file limits, plus selected `/proc/self/limits` values;
- CPU parallelism and the process CPU affinity mask;
- total/available memory and swap;
- UDP socket buffer defaults and maxima;
- UDP memory pressure thresholds and the local port range;
- network backlog/listener limits; and
- kernel/io_uring settings relevant to the six runtime backends.

The matrix's resource requirement is per process. A sender retains one UDP
socket per connection, while pooled listeners retain their listener sockets
and reuseport promotion may add one connected socket per promoted connection.
`connect-concurrency` limits simultaneous handshakes; it does not lower the
steady-state socket count.

The checked-in full matrix requests up to 1,200 connections. A soft limit of
1,024 is therefore insufficient even when the kernel has enough ports. The
startup raise normally resolves this when the hard limit permits it. The
diagnostic should be saved alongside benchmark results because memory,
affinity, socket-buffer sysctls, and io_uring availability can change the
capacity offered by the same source revision.
