# Diagnosis Guide

hotspot-bpf classifies every monitored process with a **diagnosis label**
displayed in the TUI's Focus banner and the Diagnosis column. This guide
explains what each label means, what triggers it, and what to do about it.

---

## Diagnosis Precedence

A process is evaluated against rules **top-to-bottom**. The first matching
rule wins — a process receives exactly one label per tick.

| Priority | Label | Severity |
|----------|-------|----------|
| 1 (highest) | OOM risk – memory growth | 5 |
| 2 | CPU-bound | 1 |
| 3 | Mem-thrashing | 4 |
| 4 | Starved | 3 |
| 5 | Noisy neighbor | 2 |
| 6 (lowest) | OK | 0 |

The **severity** score determines which process appears in the Focus banner
when multiple interesting processes exist. Higher severity wins.

---

## OOM risk – memory growth

**What it means:**
The process is actively growing its memory footprint while generating
sustained page-fault pressure. If this trend continues unchecked, the
process (or the system) will eventually run out of memory, potentially
triggering the kernel OOM killer.

**Trigger conditions (ALL must be true):**
- RSS is **monotonically growing** across at least 2 consecutive ticks
  (with ≥ 10 MB net increase)
- RSS ≥ 500 MB **or** RSS ≥ 10% of total system RAM
- Page fault rate ≥ 200 faults/sec

**Why trend-based detection matters:**
A large-but-stable process (e.g., a JVM using 2 GB with occasional GC
faults) is NOT an OOM risk. Only processes with actively growing RSS
trigger this classification, avoiding false positives.

**Possible consequences if ignored:**
- Kernel OOM killer terminates the process (or other processes)
- System-wide memory pressure degrades all workloads
- Swap thrashing makes the entire machine unresponsive
- In containerized environments, cgroup OOM kills the pod

**Suggested actions:**
1. Identify the leak: use `valgrind`, `tracemalloc` (Python), or
   heap profilers for your language
2. Short-term: restart the process or set a memory limit (cgroup, ulimit)
3. Check if the workload is simply under-provisioned vs. actually leaking
4. Review recent code changes that may have introduced the leak

**Example scenario:**
A Python ETL job processes data in a loop without releasing references.
RSS grows from 200 MB to 1.2 GB over 60 seconds while faulting at
1000+/sec. hotspot-bpf flags it as OOM risk after the 3rd tick (15s).

---

## CPU-bound

**What it means:**
The process is consuming significant CPU time without memory pressure or
scheduler contention. It's doing pure computation — not waiting on I/O
or fighting for resources.

**Trigger conditions (ALL must be true):**
- CPU usage > 50%
- Page fault rate < 1 fault/sec
- Preemption count = 0

**Possible consequences if ignored:**
- Other processes on the same core(s) may receive less CPU time
- Latency-sensitive workloads may be impacted
- Usually benign for batch/computation workloads

**Suggested actions:**
1. Verify this is expected (e.g., compilation, encoding, ML training)
2. If not expected, profile with `perf record` to find hot functions
3. Consider CPU pinning (`taskset`) or cgroup CPU limits
4. For multi-threaded workloads, check for spin-locks or busy-waits

**Example scenario:**
A video encoder running at 95% CPU with zero faults. This is expected
behavior and simply means the encoder is compute-bound.

---

## Mem-thrashing

**What it means:**
The process is experiencing a high rate of **expensive** page faults —
each fault costs significant CPU time. This typically indicates the
working set exceeds available RAM, causing the kernel to constantly
page data in and out.

**Trigger conditions (either set):**
- Fault rate > 1000/sec AND CPU cost per fault > 0.5ms AND CPU < 20%
- Fault rate > 500/sec AND CPU cost per fault > 0.1ms AND CPU < 20%

**Possible consequences if ignored:**
- Application throughput drops dramatically
- Latency spikes (10x–100x slower than normal)
- System may become unresponsive if swap is involved
- Can cascade to other processes sharing the same NUMA node

**Suggested actions:**
1. Check if the system is swapping (`swapon -s`, `vmstat`)
2. Increase available RAM or reduce the process's working set
3. Use huge pages (`madvise(MADV_HUGEPAGE)`) to reduce TLB misses
4. Profile memory access patterns for cache-unfriendly behavior
5. In containers, check if the memory limit is too low

**Example scenario:**
A database with a 4 GB dataset running on a 2 GB container. Every query
causes page faults as data is paged in from disk, costing 0.5ms+ per
fault. The database appears to use only 15% CPU but is actually blocked
on I/O most of the time.

---

## Starved

**What it means:**
The process is being **frequently preempted** by other processes and
is receiving very little CPU time as a result. It wants to run but
keeps getting pushed aside.

**Trigger conditions (ALL must be true):**
- Preempted > 100 times in the window
- CPU usage < 10%

**Possible consequences if ignored:**
- Increased latency for the affected process
- Timeouts in network services
- Queue buildup and cascading failures
- SLA violations in production workloads

**Suggested actions:**
1. Identify the aggressor: check the CPU Contention table for who is
   preempting this process
2. Use `chrt` or `nice` to adjust scheduling priority
3. Use CPU pinning to isolate the victim from noisy neighbors
4. In Kubernetes, set CPU requests/limits or use guaranteed QoS class

**Example scenario:**
A metrics collector running at `nice 19` is preempted 300 times per
window by a CPU-intensive build job, only getting 2% CPU. It falls
behind on metric collection and data is lost.

---

## Noisy neighbor

**What it means:**
The process is **frequently preempting other processes** while consuming
significant CPU. It's the aggressor in scheduler contention — stealing
CPU time from others.

**Trigger conditions (ALL must be true):**
- Preempts other processes > 100 times in the window
- CPU usage > 30%

**Possible consequences if ignored:**
- Other processes become "Starved" (see above)
- Unpredictable latency for co-located workloads
- In shared infrastructure, violates isolation guarantees
- Can trigger cascading slowdowns across dependent services

**Suggested actions:**
1. Apply CPU limits (cgroup, ulimit) to cap the noisy process
2. Use `taskset` to pin it to specific cores away from sensitive workloads
3. In Kubernetes, use resource limits and anti-affinity rules
4. Consider moving the workload to a dedicated node/VM
5. Profile to see if the high CPU usage is legitimate or a bug

**Example scenario:**
A log aggregator with no CPU limits runs at 45% CPU and preempts the
API server 200+ times per window. API latency spikes from 5ms to 50ms
during log rotation.

---

## OK

**What it means:**
The process doesn't match any concerning pattern. It may be idle, lightly
loaded, or simply operating normally.

**Trigger conditions:**
None of the above rules matched.

**Notes:**
- "OK" doesn't mean "doing nothing" — it means "nothing concerning"
- A process at 30% CPU with low faults and no contention is "OK"
- Check the raw metrics (CPU%, faults/sec, RSS) for more detail

---

## Troubleshooting

### "No CPU samples for this window"
No `sched_switch` events were recorded. The system may be idle, or the
BPF program may not be attached. Verify with `bpftool prog list`.

### "No preemptions recorded in this window"
Normal during low-contention periods. Preemptions only occur when the
scheduler forcibly switches tasks — cooperative yields don't count.

### "Page fault tracker unavailable"
The `handle_mm_fault` kprobe failed to attach. Check kernel version
(5.8+) and BTF availability (`ls /sys/kernel/btf/vmlinux`).

### "No processes matched current filters"
The filter flags (`-hide-kernel`, `-cgroup-filter`) excluded all
processes. Try `-hide-kernel=false` or adjust the cgroup filter.

### Focus shows a different process than expected
The Focus banner picks the **highest severity** process. If multiple
processes have the same severity, the one with the highest CPU% wins.
Check the Diagnosis column in the tables to see all labels.

### RSS shows 0.0 for a process
The BPF RSS read returned 0 (kernel thread or no `mm_struct`) and
the `/proc` fallback also failed (process may have exited). This is
expected for kernel threads and very short-lived processes.
