#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <stdbool.h>

struct fault_stat {
    u64 faults;
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

static __always_inline int record_fault(void) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0)
        return 0;

    struct fault_stat *entry = bpf_map_lookup_elem(&page_faults, &pid);
    if (entry) {
        entry->faults++;
        if (entry->cgroup[0] == '\0' && !snapshot_cgroup(entry->cgroup, sizeof(entry->cgroup)))
            write_placeholder(entry->cgroup, sizeof(entry->cgroup));
    } else {
        struct fault_stat init = {};
        init.faults = 1;
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
