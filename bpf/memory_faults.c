// memory_faults.c — eBPF program for page fault tracking with in-kernel RSS capture.
//
// Attaches as a kprobe on handle_mm_fault, which is the kernel's unified entry
// point for both minor and major page faults. Every time a process triggers a
// fault, we:
//
//  1. Increment a per-PID fault counter in the page_faults map.
//  2. Read the process's current RSS directly from task->mm->rss_stat[].count
//     (the base counter of the percpu_counter). This is approximate — it omits
//     per-CPU deltas — but accurate enough for trend-based OOM classification.
//  3. Snapshot the cgroup leaf name (best-effort, same as cpu_hotspot.c).
//
// Maps are read and cleared by the Go collector (pkg/collector/memory) each tick.

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <stdbool.h>

// Per-PID fault statistics for the current sampling window.
// Layout must match the Go faultStat struct in collector_linux.go exactly.
struct fault_stat {
    u64 faults;     // total page faults since last reset
    u64 rss_pages;  // RSS in pages, read from mm->rss_stat at fault time
    char cgroup[64];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u32);
    __type(value, struct fault_stat);
} page_faults SEC(".maps");

#ifndef bpf_get_current_task_btf
#define bpf_get_current_task_btf() bpf_get_current_task()
#endif

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

// read_rss_pages reads the approximate RSS (in pages) from the task's mm_struct.
// Sums file-backed + anonymous + shared-memory pages. The percpu_counter .count
// field is the base counter; per-CPU deltas are not included (off by at most
// batch * num_cpus pages, typically a few MB).
static __always_inline u64 read_rss_pages(struct task_struct *task) {
    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    if (!mm)
        return 0;
    s64 file  = BPF_CORE_READ(mm, rss_stat[MM_FILEPAGES].count);
    s64 anon  = BPF_CORE_READ(mm, rss_stat[MM_ANONPAGES].count);
    s64 shmem = BPF_CORE_READ(mm, rss_stat[MM_SHMEMPAGES].count);
    s64 total = file + anon + shmem;
    return total > 0 ? (u64)total : 0;
}

static __always_inline int record_fault(void) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0)
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    u64 rss = read_rss_pages(task);

    struct fault_stat *entry = bpf_map_lookup_elem(&page_faults, &pid);
    if (entry) {
        entry->faults++;
        entry->rss_pages = rss;
        if (entry->cgroup[0] == '\0' && !snapshot_cgroup(entry->cgroup, sizeof(entry->cgroup)))
            write_placeholder(entry->cgroup, sizeof(entry->cgroup));
    } else {
        struct fault_stat init = {};
        init.faults = 1;
        init.rss_pages = rss;
        if (!snapshot_cgroup(init.cgroup, sizeof(init.cgroup)))
            write_placeholder(init.cgroup, sizeof(init.cgroup));
        bpf_map_update_elem(&page_faults, &pid, &init, BPF_ANY);
    }

    return 0;
}

SEC("kprobe/handle_mm_fault")
int BPF_KPROBE(handle_mm_fault_kprobe) {
    return record_fault();
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
