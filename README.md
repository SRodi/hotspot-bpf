# hotspot-bpf

hotspot-bpf uses eBPF to turn raw kernel events into real-time performance explanations.
It correlates CPU time, scheduler contention, and page-fault pressure in a single window, revealing why a process is slow, starved, or heading toward OOM.
Traditional tools only show usage. hotspot shows **cause and effect**.

## Demo

We launch a Python memory leak, and as the process's RSS and fault rate cross the threshold, hotspot-bpf diagnoses it as an OOM-risk process by correlating CPU usage, page-fault rate, and RSS growth in real time.

![hotspot CLI demo](static/demo.gif)

`hotspot-bpf` combines **two tiny eBPF programs** with a Go TUI to answer the three questions that `top`, `htop`, and `perf` cannot answer together:

| What it reveals | Why it matters |
|------------------|----------------|
| Who is burning CPU? | Fast diagnosis of CPU-bound workloads |
| Who is stealing CPU? | Real victim/aggressor contention visibility |
| Who is stalling on memory faults? | Page-fault pressure & OOM risk detection |

All signals are sampled in **one sliding time window**, so **cause / effect** is visible instantly.

---

## What hotspot-bpf does (in one view)

- **Nanosecond-accurate CPU usage** via `sched/sched_switch`
- **Victim ↔ aggressor CPU contention** (which PID preempts which PID)
- **Real-time page fault rate** via `handle_mm_fault` kprobe
- **CPU cost per fault (ms)** — detects inefficient workloads  
- **Auto classification:**  
  `CPU-bound`, `Starved`, `Mem-thrashing`, `Noisy neighbor`, `OOM risk`, `OK`

> Traditional tools show these signals separately — hotspot cross-correlates them live.

---

## Why not top/htop/perf?

| hotspot-bpf | Traditional tools |
|-------------|-------------------|
| CPU + contention + page faults in one window | Only independent views |
| Victim/aggressor mapping | Total context switches only |
| Root-cause labels | Manual interpretation required |
| Uses eBPF tracepoints + kprobes | Mostly /proc sampling |
| cgroup-aware | Usually per-process only |

---

## Live Snapshot

```text
[!] Focus: python3 (pid 170276)
    Reason: OOM risk – memory growth – 1.1 GB RSS, 1103 faults/sec

[Top 5 CPU, window 5s]
PID     COMM        CGROUP                CPU(ms)  CPU(%)  Diag
170276  python3     session-518.scope     43.84    0.40    OOM risk – memory growth

[CPU Contention - last 5s]
No preemptions recorded in this window

[CPU Cost per Fault – CPU vs Page Faults]
PID     COMM        RSS(MB)  Faults/sec  CPU Cost/Fault (ms)  Diagnosis
170276  python3     1154.5   1102.6      0.01                 OOM risk – memory growth
```

## How it works

| File | Purpose |
|------|---------|
|bpf/cpu_hotspot.c | Tracepoint for sched/sched_switch → CPU time + contention map|
|bpf/memory_faults.c | Kprobe on handle_mm_fault → page faults + in-kernel RSS per PID|
|pkg/collector/* | Go CO-RE wrappers (generated via bpf2go)|
|pkg/report | Merges stats, classifies processes, tracks RSS trends|
|cmd/hotspot | TUI: focus banner + CPU table + contention + fault efficiency|

For detailed design and component diagrams, see **[docs/architecture.md](docs/architecture.md)**.

For a complete explanation of each diagnosis label (Focus Reason), see **[docs/diagnosis-guide.md](docs/diagnosis-guide.md)**.

## Requirements (Linux only)

| Requirement | Why it matters | Official docs / references |
|-------------|----------------|-----------------------------|
| Linux kernel 5.8+ with BTF (`/sys/kernel/btf/vmlinux`) | Enables CO-RE relocation for eBPF programs (sched tracepoint & mm fault kprobe) | [Linux BPF docs](https://www.kernel.org/doc/html/latest/bpf/index.html) |
| Go 1.24+ | Builds the CLI and runs `bpf2go` | [Go installation guide](https://go.dev/doc/install) |
| Clang + LLVM 15+ / make / pkg-config / gcc | Compiles the eBPF object code used by `bpf2go` | [LLVM Getting Started guide](https://llvm.org/docs/GettingStarted.html) |
| Matching kernel headers (`linux-headers-$(uname -r)`) | Provides exact struct/API definitions required to compile eBPF / kernel-space related code | [Kernel Headers explained – Linux Kernel Newbies](https://kernelnewbies.org/KernelHeaders) |
| `bpftool` | Dumps BTF into `bpf/vmlinux.h` and manages eBPF programs/maps | [bpftool official site](https://bpftool.dev/) |
| `bpf2go` (from `cilium/ebpf`) | Generates Go bindings + object files for the eBPF collectors | [`bpf2go` repository](https://github.com/cilium/ebpf/tree/main/cmd/bpf2go) |

macOS/Windows can build the CLI but cannot run eBPF. Use Linux for runtime testing.

## Quick Start

```sh
git clone https://github.com/srodi/hotspot-bpf.git
cd hotspot-bpf

sudo apt install clang llvm bpftool gcc linux-headers-"$(uname -r)"

go install github.com/cilium/ebpf/cmd/bpf2go@latest
export PATH="$HOME/go/bin:$PATH"

sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
go generate ./...

sudo go run ./cmd/hotspot -interval 5s -topk 5
```

## Useful flags & tips

|Flag	|Description|
|-------------|-------------------|
|-interval 2s	| Faster sampling|
|-topk 10	| Show more rows|
|-hide-kernel=false	| Include kthreads|
|-cgroup-filter pods.slice | Scope to workloads|
|-config thresholds.yaml | Custom classification thresholds|
|-generate-config | Print default config YAML and exit|

### Custom Classification Thresholds

All diagnosis thresholds are configurable via a YAML file. Generate the
default configuration as a starting point:

```sh
sudo go run ./cmd/hotspot -generate-config > thresholds.yaml
```

Edit the file to tune thresholds for your environment, then pass it at runtime:

```sh
sudo go run ./cmd/hotspot -config thresholds.yaml
```

Any value not specified in the file retains its default. See the generated
file for detailed comments explaining each parameter, or refer to
[docs/diagnosis-guide.md](docs/diagnosis-guide.md) for threshold semantics.

## Testing Scenarios

Each diagnosis can be triggered with the examples below. On **multi-core
machines** (8+ cores), single-threaded workloads produce low system-wide
CPU percentages (e.g. one busy core = 5% on a 20-core machine). Use the
provided test config to lower thresholds for reliable reproduction.

### Test Configuration (recommended for multi-core machines)

Save this as `test-thresholds.yaml` and run with `-config test-thresholds.yaml`:

```yaml
# Lowered thresholds for testing on multi-core machines.
# NOT suitable for production — will produce false positives.
oom:
  rss_mb: 200
  rss_ratio: 0.02
  faults_per_sec: 100
cpu_bound:
  cpu_percent: 3
noisy_neighbor:
  min_preempts_others: 20
  min_cpu_percent: 2
starved:
  min_preempted: 20
  max_cpu_percent: 5
mem_thrashing:
  moderate_faults_per_sec: 100
  moderate_cost_per_fault: 0.01
  severe_faults_per_sec: 500
  severe_cost_per_fault: 0.05
  max_cpu_percent: 10
```

```sh
sudo go run ./cmd/hotspot -config test-thresholds.yaml -interval 5s
```

---

### Testing CPU-bound

A tight loop with no memory allocation and no contention.

```sh
# Single-core busy loop (will show ~5% on a 20-core machine)
yes > /dev/null &
YES_PID=$!
sleep 30
kill $YES_PID
```

**Expected diagnosis**: `CPU-bound` — high CPU, near-zero faults, no preemptions.

> On multi-core machines, use `-config test-thresholds.yaml` (cpu_percent: 3)
> so that a single-core workload triggers the classification.

---

### Testing Starved + Noisy neighbor

Pin a victim and an aggressor to the **same CPU core** so the scheduler is
forced to preempt one in favour of the other. This triggers both diagnoses
simultaneously — the aggressor is the "Noisy neighbor" and the victim is
"Starved".

```sh
# Terminal 1 — Aggressor: normal-priority busy loop pinned to core 0
taskset -c 0 bash -c 'while true; do :; done' &
AGGRESSOR_PID=$!

# Terminal 2 — Victim: low-priority busy loop pinned to the SAME core
taskset -c 0 nice -n 19 bash -c 'while true; do :; done' &
VICTIM_PID=$!

# Let it run for 30 seconds
sleep 30
kill $AGGRESSOR_PID $VICTIM_PID
```

**Expected diagnoses**:
- The **victim** (nice -n 19 process) → `Starved` — preempted 100+ times,
  very low CPU%.
- The **aggressor** (normal priority) → `Noisy neighbor` — preempts the
  victim repeatedly while consuming most of the core's CPU time.

> On multi-core machines, use `-config test-thresholds.yaml` to lower the
> CPU% and preemption count thresholds. With 20 cores, a single-core
> aggressor shows ~5% system-wide CPU.

---

### Testing Mem-thrashing

Force expensive page faults by repeatedly discarding pages with
`madvise(MADV_DONTNEED)` and then re-accessing them. Each re-fault costs
CPU time to re-zero or re-populate the page.

```sh
python3 - << 'THRASH'
import mmap, os, time, random

# Allocate 256 MB of anonymous memory
size = 256 * 1024 * 1024
mm = mmap.mmap(-1, size, prot=mmap.PROT_READ | mmap.PROT_WRITE)

# Repeatedly discard and re-fault pages
while True:
    # Tell kernel to drop all pages — next access triggers new faults
    mm.madvise(mmap.MADV_DONTNEED)
    # Touch pages in random order to trigger faults
    for _ in range(5000):
        offset = random.randint(0, size - 4096) & ~4095
        mm[offset] = 65  # triggers a page fault
    time.sleep(0.1)      # keep CPU% low
THRASH
```

**Expected diagnosis**: `Mem-thrashing` — high fault rate (500+/sec), each
fault costs measurable CPU time, but total CPU% stays below 20%.

> The `time.sleep(0.1)` keeps CPU usage low. Without it the process may
> classify as OK or CPU-bound instead, since faults become too cheap
> relative to total CPU.

---

### Testing OOM risk – memory growth

A Python memory leak that allocates ~40 MB/s. RSS crosses the 500 MB
detection threshold in about 25 seconds (roughly 5 sampling windows at the
default 5s interval). The RSS trend tracker needs at least 2 consecutive
ticks of growth before flagging OOM.

```sh
python3 - << 'EOF'
import time
x = []
while True:
    x.append(' ' * 10_000_000)  # ~10 MB per iteration
    time.sleep(0.25)
EOF
```

**Expected diagnosis**: `OOM risk – memory growth` — RSS is growing
monotonically with high fault rate. Appears after ~15–25 seconds depending
on your sampling interval.

> ⚠️ **Kill the process before it exhausts system memory.** Use Ctrl+C or
> `kill` from another terminal. On a 32 GB machine you have several minutes.

---

### Quick Reference

| Diagnosis | Workload | Key Signal | Appears After |
|-----------|----------|------------|---------------|
| CPU-bound | `yes > /dev/null` | High CPU, no faults | 1 tick (5s) |
| Starved | `nice -n 19` victim pinned with aggressor | High preemption, low CPU | 1 tick (5s) |
| Noisy neighbor | Normal-priority aggressor pinned with victim | High preempts-others, moderate CPU | 1 tick (5s) |
| Mem-thrashing | Python madvise loop | High fault rate, costly faults, low CPU | 1 tick (5s) |
| OOM risk | Python memory leak | Growing RSS + high faults | 2–3 ticks (10–15s) |
