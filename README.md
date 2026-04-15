# hotspot-bpf

**eBPF performance lens** — real-time root-cause diagnosis for Linux processes.

hotspot-bpf correlates CPU time, scheduler contention, page-fault pressure, and RSS growth in a single terminal view. Instead of showing raw numbers and leaving interpretation to you, it tells you **why** a process is slow, starved, or heading toward OOM.

> Two small eBPF programs. One Go binary. Zero dependencies at runtime.

![hotspot-bpf detecting an OOM-risk memory leak in real time](static/hotspot-oom.png)

---

## What it detects

hotspot automatically classifies every visible process into one of six diagnoses — heuristic labels derived from one sampling window:

| Diagnosis | Meaning |
|-----------|---------|
| **OOM risk** | RSS growing monotonically + high page-fault rate |
| **CPU-bound** | Saturating a CPU core with no memory pressure |
| **Mem-thrashing** | High-rate page faults that cost real CPU time |
| **Starved** | Frequently preempted, getting little CPU |
| **Noisy neighbor** | Preempting others while consuming significant CPU |
| **OK** | No anomaly detected |

All thresholds are [configurable via YAML](#custom-thresholds).

---

## Quick start

### Runtime requirements

| Requirement | Notes |
|-------------|-------|
| **Linux kernel ≥ 5.5** with BTF | `ls /sys/kernel/btf/vmlinux` must succeed. Recommended ≥ 5.8 for broadest kprobe compatibility. |
| **root** or `CAP_BPF` + `CAP_PERFMON` | eBPF program loading requires elevated privileges |
| x86_64 | ARM64 support is not yet available |

### Build requirements

| Tool | Purpose |
|------|---------|
| [Go 1.24+](https://go.dev/doc/install) | Builds the CLI |
| [Clang / LLVM 15+](https://llvm.org/docs/GettingStarted.html) | Compiles eBPF C to BPF bytecode |
| [bpftool](https://bpftool.dev/) | Generates `vmlinux.h` from kernel BTF |
| [bpf2go](https://github.com/cilium/ebpf/tree/main/cmd/bpf2go) | Generates Go bindings for eBPF objects |
| linux-headers | Kernel struct definitions for eBPF compilation |

> macOS / Windows can cross-compile the Go binary but cannot run eBPF. Use Linux for testing.

### Build and run

```sh
git clone https://github.com/srodi/hotspot-bpf.git
cd hotspot-bpf

# Install build dependencies (Debian/Ubuntu)
sudo apt install clang llvm bpftool gcc linux-headers-"$(uname -r)"
go install github.com/cilium/ebpf/cmd/bpf2go@latest
export PATH="$HOME/go/bin:$PATH"

# Generate BPF bindings
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
go generate ./...

# Run
sudo go run ./cmd/hotspot -interval 5s -topk 5
```

---

## What hotspot adds beyond top/htop/perf

| Capability | hotspot-bpf | top / htop | perf |
|------------|-------------|------------|------|
| CPU + contention + faults in one view | ✅ | ❌ separate tools | ❌ separate subcommands |
| Victim ↔ aggressor mapping | ✅ who preempted whom | ❌ total context switches only | partial (perf sched) |
| Per-core saturation detection | ✅ flags single-core bottlenecks | ❌ system-wide % only | ❌ |
| Automatic root-cause labels | ✅ | ❌ manual interpretation | ❌ |
| RSS growth trend tracking | ✅ detects leaks over time | ❌ point-in-time snapshot | ❌ |
| cgroup-aware filtering | ✅ | limited | ✅ |
| Zero instrumentation | ✅ eBPF tracepoints + kprobes | ✅ /proc sampling | ✅ PMU / tracepoints |

hotspot is not a replacement for `perf` — it's a **triage tool** that answers "what's wrong right now?" in seconds, so you know where to dig deeper.

---

## How it works

```
  Kernel                    BPF Programs              BPF Maps                Go Userspace
┌──────────────────┐   ┌──────────────────┐   ┌──────────────────┐   ┌──────────────────────┐
│ tp_btf/          │──▶│ cpu_hotspot.c    │──▶│ pid_stats        │──▶│ cpu.Collector         │
│ sched_switch     │   │ (CPU time +      │   │ cpu_contention   │   │                       │
│ (BTF raw TP)     │   │  contention +    │   │ (per-TGID)       │   │ report.BuildProcMetrics│
│                  │   │  core tracking)  │   │                  │   │ ├─ merge CPU + memory  │
├──────────────────┤   ├──────────────────┤   ├──────────────────┤   │ ├─ classify process    │
│ handle_mm_fault  │──▶│ memory_faults.c  │──▶│ page_faults      │──▶│ └─ track RSS trend    │
│ (kprobe)         │   │ (faults + RSS)   │   │ (per-TGID)       │   │                       │
│                  │   │                  │   │                  │   │ TUI (flicker-free)    │
└──────────────────┘   └──────────────────┘   └──────────────────┘   └──────────────────────┘
```

All BPF maps are keyed by **TGID** (process ID), ensuring CPU and memory data merges correctly even for multi-threaded applications. Maps are reset after each sampling window — metrics reflect only the current interval, not cumulative totals.

| Component | File | Role |
|-----------|------|------|
| CPU collector | `bpf/cpu_hotspot.c` | `tp_btf/sched_switch` → nanosecond CPU time, victim/aggressor contention, CPU core ID |
| Memory collector | `bpf/memory_faults.c` | `handle_mm_fault` kprobe → page fault count + in-kernel RSS |
| Collectors (Go) | `pkg/collector/` | CO-RE wrappers generated by bpf2go; read and reset BPF maps |
| Report engine | `pkg/report/` | Merges CPU + memory stats, classifies processes, tracks RSS trends |
| TUI | `cmd/hotspot/` | Flicker-free terminal UI with colorized diagnosis labels |
| Config | `pkg/config/` | YAML-driven thresholds with commented defaults |

📖 **[Architecture deep-dive](docs/architecture.md)** · 📖 **[Diagnosis guide](docs/diagnosis-guide.md)**

---

## CLI flags

| Flag | Default | Description |
|------|---------|-------------|
| `-interval` | `5s` | Sampling window duration |
| `-topk` | `10` | Rows per table section |
| `-hide-kernel` | `true` | Hide kernel threads (kworker, ksoftirqd, …) |
| `-cgroup-filter` | | Only show processes whose cgroup contains this substring |
| `-config` | | Path to YAML threshold config file |
| `-generate-config` | | Print default config YAML to stdout and exit |

---

## Custom thresholds

All diagnosis thresholds are configurable. Generate the defaults as a starting point:

```sh
sudo go run ./cmd/hotspot -generate-config > thresholds.yaml
```

Edit to taste, then pass at runtime:

```sh
sudo go run ./cmd/hotspot -config thresholds.yaml -interval 5s
```

Any value not specified in the file retains its compiled-in default. See [`thresholds.yaml`](thresholds.yaml) for detailed comments explaining every parameter and how to tune it.

---

## Testing scenarios

Every diagnosis can be reproduced with the scripts below. On **multi-core machines** (8+ cores), single-threaded workloads produce low system-wide CPU% (one busy core ≈ 5% on a 20-core host). Use the test config to lower thresholds.

<details>
<summary><strong>Test config for multi-core machines</strong></summary>

Save as `test-thresholds.yaml` — **not suitable for production** (will produce false positives):

```yaml
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

</details>

<details>
<summary><strong>CPU-bound</strong> — tight loop with no memory pressure</summary>

```sh
yes > /dev/null &
YES_PID=$!
sleep 30
kill $YES_PID
```

**Expected**: `CPU-bound` — high per-core CPU%, near-zero faults, minimal preemptions.

> On multi-core machines, use `-config test-thresholds.yaml` so a single-core workload triggers classification.

</details>

<details>
<summary><strong>Starved + Noisy neighbor</strong> — two processes pinned to one core</summary>

```sh
# Aggressor: normal-priority busy loop on core 0
taskset -c 0 bash -c 'while true; do :; done' &
AGGRESSOR=$!

# Victim: low-priority busy loop on the SAME core
taskset -c 0 nice -n 19 bash -c 'while true; do :; done' &
VICTIM=$!

sleep 30
kill $AGGRESSOR $VICTIM
```

**Expected**:
- Victim → `Starved` — preempted 100+ times, very low CPU%
- Aggressor → `Noisy neighbor` — preempts the victim repeatedly

> Use `-config test-thresholds.yaml` on multi-core machines.

</details>

<details>
<summary><strong>Mem-thrashing</strong> — expensive re-faulting via madvise</summary>

```sh
python3 - << 'THRASH'
import mmap, time, random

size = 256 * 1024 * 1024
mm = mmap.mmap(-1, size, prot=mmap.PROT_READ | mmap.PROT_WRITE)

while True:
    mm.madvise(mmap.MADV_DONTNEED)
    for _ in range(5000):
        offset = random.randint(0, size - 4096) & ~4095
        mm[offset] = 65
    time.sleep(0.1)
THRASH
```

**Expected**: `Mem-thrashing` — high fault rate (500+/sec), measurable CPU cost per fault, low total CPU%.

> The `time.sleep(0.1)` keeps CPU low. Without it, faults become too cheap relative to CPU and the process may classify as OK.

</details>

<details>
<summary><strong>OOM risk</strong> — Python memory leak (~40 MB/s)</summary>

```sh
python3 - << 'EOF'
import time
x = []
while True:
    x.append(' ' * 10_000_000)
    time.sleep(0.25)
EOF
```

**Expected**: `OOM risk – memory growth` — RSS growing monotonically + high fault rate. Appears after 2–3 sampling ticks (~10–15s).

> ⚠️ **Kill before it exhausts memory.** Ctrl+C or `kill` from another terminal.

</details>

### Quick reference

| Diagnosis | Workload | Key signal | Appears after |
|-----------|----------|------------|---------------|
| CPU-bound | `yes > /dev/null` | High per-core CPU%, no faults | 1 tick (5s) |
| Starved | `nice -n 19` victim pinned with aggressor | High preemption, low CPU | 1 tick (5s) |
| Noisy neighbor | Normal-priority aggressor pinned with victim | High preempts-others | 1 tick (5s) |
| Mem-thrashing | Python madvise loop | High fault rate, costly faults | 1 tick (5s) |
| OOM risk | Python memory leak | Growing RSS + high faults | 2–3 ticks |

---

## Screenshots

| OOM risk detection | Noisy neighbor / Starved | Mem-thrashing |
|:------------------:|:------------------------:|:-------------:|
| ![OOM](static/hotspot-oom.png) | ![Noisy](static/hotspot-noisy-neighbour.png) | ![Thrash](static/hotspot.png) |

---

## License

[MIT](LICENSE)
