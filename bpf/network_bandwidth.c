// network_bandwidth.c — eBPF program for per-process network bandwidth tracking.
//
// Accounts every packet (all protocols) to the process that owns the socket,
// split into egress and ingress byte/packet counters. Because the cgroup_skb
// hooks run in softirq context — where the current process is not the socket's
// owner — ownership is resolved via the socket cookie:
//
//  1. track_sock_create (cgroup/sock_create) records cookie -> {pid, comm} when
//     a process creates a socket. This covers the client side.
//  2. track_accept (fexit/inet_csk_accept) records ownership for the child
//     socket accept() hands back, which sock_create never sees. This covers the
//     server side, whose received bytes would otherwise land under PID 0.
//  3. count_egress / count_ingress (cgroup_skb) look the cookie up on every
//     packet and add its length to the owner's per-PID counter (0 = unattributed).
//  4. on_exit (sched_process_exit) reclaims a process's counters when it exits.
//
// Maps are read and cleared by the Go collector (pkg/collector/network) each tick.

#include "vmlinux.h"            
#include <bpf/bpf_helpers.h>   
#include <bpf/bpf_tracing.h>   

/* A simple counter: total bytes, total packets and name. */
struct netstat {
    __u64 bytes;
    __u64 packets;
    char  comm[16];
};

/* Who owns a socket: cookie -> {pid, comm}. */
struct owner {
    __u32 pid;
    char  comm[16];
};

/* cookie -> owner. LRU so the kernel evicts the oldest entries once the map is full; */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);             
    __type(value, struct owner);
} cookie_to_owner SEC(".maps");

/* Per-process EGRESS wire-ish bytes. Key 0 is reserved for UNATTRIBUTED. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);              
    __type(value, struct netstat);
} egress_by_pid SEC(".maps");

/* Per-process INGRESS wire-ish bytes. Key 0 = UNATTRIBUTED. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct netstat);
} ingress_by_pid SEC(".maps");

/* Shared helper: add this packet's bytes to the given map, under the given PID. */
static __always_inline void account(void *map, __u32 pid, const char *comm, __u64 bytes) {
    struct netstat *s = bpf_map_lookup_elem(map, &pid);
    if (s) {
        __sync_fetch_and_add(&s->bytes, bytes);
        __sync_fetch_and_add(&s->packets, 1);
    } else {
        struct netstat init = {};
        init.bytes = bytes;
        init.packets = 1;
        if (comm)
            __builtin_memcpy(&init.comm, comm, sizeof(init.comm)); 
        bpf_map_update_elem(map, &pid, &init, BPF_ANY);
    }
}

/* Resolve a packet's owner (pid + name) via its socket cookie. NULL if unknown. */
static __always_inline struct owner *owner_from_skb(struct __sk_buff *skb) {
    __u64 cookie = bpf_get_socket_cookie(skb);
    return bpf_map_lookup_elem(&cookie_to_owner, &cookie);
}

/* Record socket ownership at creation time. Runs in process context, so
 * bpf_get_current_pid_tgid() is the creating process (the client path). */
SEC("cgroup/sock_create")
int track_sock_create(struct bpf_sock *ctx) {
    __u64 cookie = bpf_get_socket_cookie(ctx);
    struct owner o = {};
    o.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&o.comm, sizeof(o.comm));
    bpf_map_update_elem(&cookie_to_owner, &cookie, &o, BPF_ANY);
    return 1;   /* allow */
}

/* Every outgoing packet, all protocols. */
SEC("cgroup_skb/egress")
int count_egress(struct __sk_buff *skb) {
    struct owner *o = owner_from_skb(skb);
    __u32 pid       = o ? o->pid  : 0;      // 0 = unattributed
    const char *nm  = o ? o->comm : 0;
    account(&egress_by_pid, pid, nm, skb->len);
    return 1;   /* 1 = ALLOW; never return 0 or you drop traffic */
}

/* Every incoming packet, all protocols. */
SEC("cgroup_skb/ingress")
int count_ingress(struct __sk_buff *skb) {
    struct owner *o = owner_from_skb(skb);
    __u32 pid       = o ? o->pid  : 0;
    const char *nm  = o ? o->comm : 0;
    account(&ingress_by_pid, pid, nm, skb->len);
    return 1;   /* ALLOW */
}

/* Record socket ownership when a server accept()s a new connection.
 * cgroup/sock_create only fires for sockets a process creates itself, not for
 * the child socket accept() returns, so without this the server's received
 * bytes have no owner and land under PID 0. fexit runs after inet_csk_accept
 * returns, in the accepting process's context, so bpf_get_current_pid_tgid()
 * is the server process.
 *
 * NOTE: inet_csk_accept's signature changed around kernel 6.12 (the
 * flags/err/kern args became a single proto_accept_arg *). Use the argument
 * list matching the target kernel; only the final newsk arg is read. */
SEC("fexit/inet_csk_accept")
int BPF_PROG(track_accept, struct sock *sk, int flags, int *err, bool kern, struct sock *newsk) { // 4 arg (AKS)
    if (!newsk)
        return 0;                 /* accept() failed, nothing to record */
    __u64 cookie = bpf_get_socket_cookie(newsk);
    struct owner o = {};
    o.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&o.comm, sizeof(o.comm));
    bpf_map_update_elem(&cookie_to_owner, &cookie, &o, BPF_ANY);
    return 0;
}

/* Clean up per-PID entries when a process fully exits. */
SEC("tracepoint/sched/sched_process_exit")
int on_exit(void *ctx) {
    __u64 id  = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;
    __u32 tid = (__u32)id;
    if (pid != tid)          /* only when the whole process exits */
        return 0;
    bpf_map_delete_elem(&egress_by_pid, &pid);
    bpf_map_delete_elem(&ingress_by_pid, &pid);
    return 0;
}

/* GPL-compatible license is required: several helpers used here (socket cookie,
 * current comm, etc.) are only available to GPL-licensed BPF programs. */
char LICENSE[] SEC("license") = "Dual BSD/GPL";