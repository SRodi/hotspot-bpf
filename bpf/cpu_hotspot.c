// cpu_hotspot.c — eBPF program for CPU usage and scheduler contention tracking.
//
// Attaches to the sched/sched_switch tracepoint, which fires every time the
// kernel scheduler moves a CPU from one task to another. On each switch we:
//
//  1. Record a victim→aggressor contention pair (prev_pid preempted by next_pid)
//     in the cpu_contention map. The key is a packed u64: (victim<<32 | aggressor).
//
//  2. Accumulate nanosecond-accurate CPU time for the outgoing PID by computing
//     the delta between the current timestamp and the last switch timestamp
//     stored in the per-CPU cpu_state array.
//
//  3. Snapshot the process name (comm) and cgroup leaf name for display in the TUI.
//
// Maps are read and cleared by the Go collector (pkg/collector/cpu) each tick.

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <stdbool.h>

// Per-CPU scratch space: tracks which PID was last running and when.
// Using a PERCPU_ARRAY with a single key avoids lock contention.
struct cpu_state {
	u32 pid;
	u64 ts;
};

// Per-PID cumulative CPU time + metadata for the current sampling window.
struct pid_stat {
	u64 cpu_time_ns;
	char comm[16];
	char cgroup[64];
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

// Contention map: key = (victim_pid << 32 | aggressor_pid), value = count.
// Records how many times aggressor preempted victim within the window.
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

SEC("tracepoint/sched/sched_switch")
int handle_sched_switch(struct trace_event_raw_sched_switch *ctx) {
	u64 ts = bpf_ktime_get_ns();
	u32 key = 0; // index into per-CPU array always 0

	struct cpu_state *st = bpf_map_lookup_elem(&cpu_state, &key);
	if (!st)
		return 0;

	u32 victim = ctx->prev_pid;
	u32 aggressor = ctx->next_pid;

	// Track contention: when a non-idle task is switched out in favour of
	// another non-idle task, record the pair so we can identify which
	// processes are stealing CPU time from others.
	if (victim != 0 && aggressor != 0) {
		u64 pair = ((u64)victim << 32) | aggressor;
		u64 *cnt = bpf_map_lookup_elem(&cpu_contention, &pair);
		if (cnt) {
			(*cnt)++;
		} else {
			u64 init = 1;
			bpf_map_update_elem(&cpu_contention, &pair, &init, BPF_ANY);
		}
	}

	// If previous PID was non-zero, update its CPU time
	if (st->pid != 0) {
		u64 delta = ts - st->ts;
		u32 pid = st->pid;

		struct pid_stat *ps = bpf_map_lookup_elem(&pid_stats, &pid);
		if (!ps) {
			struct pid_stat new_ps = {};
			new_ps.cpu_time_ns = delta;
			bpf_get_current_comm(new_ps.comm, sizeof(new_ps.comm));
			if (!snapshot_cgroup(new_ps.cgroup, sizeof(new_ps.cgroup)))
				write_placeholder(new_ps.cgroup, sizeof(new_ps.cgroup));
			bpf_map_update_elem(&pid_stats, &pid, &new_ps, BPF_ANY);
		} else {
			ps->cpu_time_ns += delta;
			if (ps->cgroup[0] == '\0' && !snapshot_cgroup(ps->cgroup, sizeof(ps->cgroup)))
				write_placeholder(ps->cgroup, sizeof(ps->cgroup));
			if (ps->comm[0] == '\0')
				bpf_get_current_comm(ps->comm, sizeof(ps->comm));
		}
	}

	// Update for the next PID
	u32 next_pid = ctx->next_pid;
	st->pid = next_pid;
	st->ts = ts;

	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
