#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct syscall_event {
    __u8 kind;
    __u8 _pad0[3];
    __u64 ts_ns;
    __u32 pid;
    __u32 cpu;
    __u32 id;
    __u64 latency_ns;
    char comm[16];
};

struct tcp_retransmit_event {
    __u8 kind;
    __u8 _pad0[3];
    __u64 ts_ns;
    __u32 pid;
    __u32 cpu;
    __u16 family;
    __u16 lport;
    __u16 dport;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, __u64);
} syscall_start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

static __always_inline void increment_counter(__u32 key) {
    __u64 *value = bpf_map_lookup_elem(&counters, &key);
    if (value) {
        __sync_fetch_and_add(value, 1);
    }
}

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_sys_enter(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&syscall_start, &pid_tgid, &ts, BPF_ANY);
    increment_counter(0);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int trace_sys_exit(struct trace_event_raw_sys_exit *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 now = bpf_ktime_get_ns();
    __u64 *start = bpf_map_lookup_elem(&syscall_start, &pid_tgid);
    __u64 latency = 0;
    struct syscall_event *event;

    if (start) {
        latency = now - *start;
        bpf_map_delete_elem(&syscall_start, &pid_tgid);
    }

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        increment_counter(3);
        return 0;
    }

    event->ts_ns = now;
    event->kind = 1;
    event->pid = pid_tgid >> 32;
    event->cpu = bpf_get_smp_processor_id();
    event->id = (__u32)ctx->id;
    event->latency_ns = latency;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_ringbuf_submit(event, 0);
    increment_counter(1);

    return 0;
}

SEC("tracepoint/tcp/tcp_retransmit_skb")
int trace_tcp_retransmit(struct trace_event_raw_tcp_event_sk_skb *ctx) {
    struct tcp_retransmit_event *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        increment_counter(3);
        return 0;
    }

    event->ts_ns = bpf_ktime_get_ns();
    event->kind = 2;
    event->pid = pid_tgid >> 32;
    event->cpu = bpf_get_smp_processor_id();
    event->family = ctx->family;
    event->lport = ctx->sport;
    event->dport = bpf_ntohs(ctx->dport);
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);
    increment_counter(2);
    return 0;
}
