// cpu_hotspot.c — eBPF program for CPU usage and scheduler contention tracking.
//
// Uses a BTF-powered raw tracepoint (tp_btf/sched_switch) which provides direct
// access to both the outgoing and incoming task_struct pointers. This lets us
// read each task's TGID (thread group ID = process ID) without any lookup map,
// solving the PID/TID mismatch that previously caused CPU data to be keyed by
// thread ID while memory data was keyed by process ID.
//
// On every context switch we:
//
//  1. Record a victim→aggressor contention pair keyed by TGID (process-level).
//     Intra-process thread switches (same TGID) are ignored since they are not
//     true contention.
//
//  2. Accumulate nanosecond-accurate CPU time for the outgoing process (TGID).
//     Multiple threads of the same process contribute to a single pid_stats entry.
//
//  3. Snapshot the process name (comm) and cgroup leaf name for display in the TUI.
//
// Maps are read and cleared by the Go collector (pkg/collector/cpu) each tick.
//
// Requires: kernel ≥5.5 with BTF support (CONFIG_DEBUG_INFO_BTF=y).

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <stdbool.h>

// Per-CPU scratch space: tracks which process (TGID) was last running and when.
// Using a PERCPU_ARRAY with a single key avoids lock contention between CPUs.
struct cpu_state {
	u32 tgid; // TGID of the task that was last running on this CPU
	u64 ts;   // ktime_ns timestamp when that task was switched in
};

// Per-process (TGID) cumulative CPU time + metadata for the current sampling
// window. When multiple threads of the same process run on different cores,
// their CPU time is aggregated into a single entry keyed by the shared TGID.
//
// cpu_id is the last CPU core observed at switch-out (not necessarily stable
// for migratory workloads — it's a snapshot, not a primary-core assignment).
struct pid_stat {
	u64 cpu_time_ns;
	char comm[16];
	char cgroup[64];
	u32 cpu_id;
	u32 _pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct cpu_state);
} cpu_state SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);   // plenty for MVP
	__type(key, u32);
	__type(value, struct pid_stat);
} pid_stats SEC(".maps");

// Contention map: key = (victim_tgid << 32 | aggressor_tgid), value = count.
// Records how many times one process's threads preempted another process's
// threads within the window. Keyed by TGID so intra-process thread switches
// are filtered out.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 2048);
	__type(key, u64);
	__type(value, u64);
} cpu_contention SEC(".maps");

#ifndef bpf_get_current_task_btf
#define bpf_get_current_task_btf() bpf_get_current_task()
#endif

// write_placeholder fills dst with "n/a" when cgroup resolution fails.
static __always_inline void write_placeholder(char *dst, size_t len) {
	if (!dst || len == 0)
		return;
	__builtin_memset(dst, 0, len);
	if (len > 0)
		dst[0] = 'n';
	if (len > 1)
		dst[1] = '/';
	if (len > 2)
		dst[2] = 'a';
}

// snapshot_cgroup reads the leaf cgroup name for the current task via
// task->cgroups->dfl_cgrp->kn->name. Falls back to the parent kernfs node
// if the leaf name is empty. This is best-effort and not a full path.
static __always_inline bool snapshot_cgroup(char *dst, size_t len) {
	if (!dst || len == 0)
		return false;
	__builtin_memset(dst, 0, len);

	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
	if (!task)
		return false;

	struct css_set *cset = BPF_CORE_READ(task, cgroups);
	if (!cset)
		return false;
	struct cgroup *cgrp = BPF_CORE_READ(cset, dfl_cgrp);
	if (!cgrp)
		return false;
	struct kernfs_node *kn = BPF_CORE_READ(cgrp, kn);
	if (!kn)
		return false;

	const char *leaf = BPF_CORE_READ(kn, name);
	if (leaf && bpf_core_read_str(dst, len, leaf) > 0)
		return true;
	struct kernfs_node *parent_kn = BPF_CORE_READ(kn, parent);
	if (parent_kn) {
		const char *parent = BPF_CORE_READ(parent_kn, name);
		if (parent)
			return bpf_core_read_str(dst, len, parent) > 0;
	}
	return false;
}

// handle_sched_switch runs on every CPU context switch via tp_btf/sched_switch.
//
// The BPF_PROG macro unpacks the raw tracepoint arguments into typed params:
//   - preempt: whether this was a preemptive switch
//   - prev:    task_struct of the outgoing (descheduled) task
//   - next:    task_struct of the incoming (about to run) task
//
// Having direct task_struct access lets us read each task's tgid field,
// ensuring all maps are keyed by process ID (TGID) rather than thread ID.
SEC("tp_btf/sched_switch")
int BPF_PROG(handle_sched_switch, bool preempt,
	     struct task_struct *prev, struct task_struct *next) {
	u64 ts = bpf_ktime_get_ns();
	u32 key = 0; // index into per-CPU array always 0

	struct cpu_state *st = bpf_map_lookup_elem(&cpu_state, &key);
	if (!st)
		return 0;

	// Read TGIDs directly from task_struct — guaranteed correct for both
	// single-threaded and multi-threaded processes.
	u32 prev_tgid = BPF_CORE_READ(prev, tgid);
	u32 next_tgid = BPF_CORE_READ(next, tgid);

	// Track contention: when a non-idle process is switched out in favour of
	// a different non-idle process, record the pair. Intra-process switches
	// (same TGID, different threads) are NOT contention and are skipped.
	if (prev_tgid != 0 && next_tgid != 0 && prev_tgid != next_tgid) {
		u64 pair = ((u64)prev_tgid << 32) | next_tgid;
		u64 *cnt = bpf_map_lookup_elem(&cpu_contention, &pair);
		if (cnt) {
			(*cnt)++;
		} else {
			u64 init = 1;
			bpf_map_update_elem(&cpu_contention, &pair, &init, BPF_ANY);
		}
	}

	// Accumulate CPU time for the process that was running on this core.
	// st->tgid was stored when this task was previously switched IN.
	if (st->tgid != 0) {
		u64 delta = ts - st->ts;
		u32 tgid = st->tgid;
		u32 cpu = bpf_get_smp_processor_id();

		struct pid_stat *ps = bpf_map_lookup_elem(&pid_stats, &tgid);
		if (!ps) {
			struct pid_stat new_ps = {};
			new_ps.cpu_time_ns = delta;
			new_ps.cpu_id = cpu;
			bpf_get_current_comm(new_ps.comm, sizeof(new_ps.comm));
			if (!snapshot_cgroup(new_ps.cgroup, sizeof(new_ps.cgroup)))
				write_placeholder(new_ps.cgroup, sizeof(new_ps.cgroup));
			bpf_map_update_elem(&pid_stats, &tgid, &new_ps, BPF_ANY);
		} else {
			ps->cpu_time_ns += delta;
			ps->cpu_id = cpu;
			if (ps->cgroup[0] == '\0' && !snapshot_cgroup(ps->cgroup, sizeof(ps->cgroup)))
				write_placeholder(ps->cgroup, sizeof(ps->cgroup));
			if (ps->comm[0] == '\0')
				bpf_get_current_comm(ps->comm, sizeof(ps->comm));
		}
	}

	// Record the incoming process so we can attribute its CPU time on the
	// next switch-out from this core.
	st->tgid = next_tgid;
	st->ts = ts;

	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
