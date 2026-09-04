# Source this file when classifying the checked-in Stage B plans.
#
# Host: 6-vCPU AMD EPYC, 11 GiB RAM, one NUMA node, loopback only.
# Kernel: 6.8.0-137-generic. rustc: 1.96.0.
# net.core.rmem_max and net.core.wmem_max are both 268435456 bytes.
#
# Effective buffers are recorded as the requested 16 MiB: the kernel maxima
# make that request satisfiable. Live rows must still validate the observed
# effective values from their socket telemetry.
#
# Loopback has no physical NIC capacity, so the classifier must receive its
# explicit NotApplicable value. Loss and reorder are configured as real zero
# values. RTT, jitter, and host PPS are deliberately unknown: system-info and
# sysprof do not establish defensible capacity numbers for them.
HOST_ENVELOPE_ARGS=(
  --effective-receive-buffer=16777216
  --effective-send-buffer=16777216
  --nic=loopback
  --link-loss=0
  --link-reorder=0
  --host-pps-capacity=unknown
)
