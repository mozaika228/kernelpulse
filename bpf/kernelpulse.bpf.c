#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef BPF_MAP_TYPE_HASH
#define BPF_MAP_TYPE_HASH 1
#endif
#ifndef BPF_MAP_TYPE_ARRAY
#define BPF_MAP_TYPE_ARRAY 2
#endif
#ifndef BPF_MAP_TYPE_PERCPU_ARRAY
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#endif
#ifndef BPF_MAP_TYPE_RINGBUF
#define BPF_MAP_TYPE_RINGBUF 27
#endif
#ifndef BPF_ANY
#define BPF_ANY 0
#endif
#ifndef AF_INET
#define AF_INET 2
#endif

char LICENSE[] SEC("license") = "Dual BSD/GPL";

enum event_kind {
    EVENT_SYSCALL_LATENCY = 1,
    EVENT_TCP_RETRANSMIT = 2,
    EVENT_TCP_RTT = 3,
    EVENT_PAGE_FAULT = 4,
    EVENT_SCHED_LATENCY = 5,
    EVENT_EXEC = 6,
};

enum counter_key {
    COUNTER_SYS_ENTER = 0,
    COUNTER_SYS_EXIT = 1,
    COUNTER_TCP_RETRANS = 2,
    COUNTER_RINGBUF_DROPS = 3,
    COUNTER_PAGE_FAULT = 4,
    COUNTER_SCHED_WAKE = 5,
    COUNTER_SCHED_SWITCH = 6,
    COUNTER_EXEC = 7,
    COUNTER_TCP_RTT = 8,
};

struct filter_config {
    __u32 pid;
    __u32 uid;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u16 family;
    char comm[16];
    __u8 comm_set;
    __u8 _pad[1];
};

struct event_header {
    __u8 kind;
    __u8 _pad0[3];
    __u64 ts_ns;
    __u32 pid;
    __u32 cpu;
    char comm[16];
};

struct syscall_latency_event {
    struct event_header h;
    __u32 syscall_id;
    __u32 _pad1;
    __u64 latency_ns;
};

struct tcp_retransmit_event {
    struct event_header h;
    __u16 family;
    __u16 lport;
    __u16 dport;
    __u16 _pad1;
    __u32 saddr;
    __u32 daddr;
};

struct tcp_rtt_event {
    struct event_header h;
    __u16 family;
    __u16 sport;
    __u16 dport;
    __u16 _pad1;
    __u32 saddr;
    __u32 daddr;
    __u32 srtt_us;
};

struct page_fault_event {
    struct event_header h;
    __u8 kernel_fault;
    __u8 _pad1[7];
};

struct sched_latency_event {
    struct event_header h;
    __u32 prev_pid;
    __u32 next_pid;
    __u64 runq_latency_ns;
};

struct exec_event {
    struct event_header h;
    char filename[64];
};

struct syscall_enter_ctx {
    __u64 start_ts_ns;
    __u32 syscall_id;
    __u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct syscall_enter_ctx);
} syscall_start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, __u64);
} sched_wakeup_ts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct filter_config);
} filters SEC(".maps");

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

static __always_inline int str_eq_16(const char a[16], const char b[16]) {
    int i;
    for (i = 0; i < 16; i++) {
        if (a[i] != b[i]) {
            return 0;
        }
        if (a[i] == '\0') {
            break;
        }
    }
    return 1;
}

static __always_inline int pass_filter(void) {
    __u32 key = 0;
    struct filter_config *f = bpf_map_lookup_elem(&filters, &key);
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 pid = pid_tgid >> 32;
    __u32 uid = (__u32)uid_gid;
    char current_comm[16];

    if (!f) {
        return 1;
    }
    if (f->pid != 0 && f->pid != pid) {
        return 0;
    }
    if (f->uid != 0 && f->uid != uid) {
        return 0;
    }
    if (!f->comm_set) {
        return 1;
    }

    if (bpf_get_current_comm(&current_comm, sizeof(current_comm)) < 0) {
        return 0;
    }
    return str_eq_16(current_comm, f->comm);
}

static __always_inline int pass_tcp_filter(__u16 family, __u16 sport, __u16 dport, __u32 saddr, __u32 daddr) {
    __u32 key = 0;
    struct filter_config *f = bpf_map_lookup_elem(&filters, &key);

    if (!f) {
        return 1;
    }
    if (f->family != 0 && f->family != family) {
        return 0;
    }
    if (f->sport != 0 && f->sport != sport) {
        return 0;
    }
    if (f->dport != 0 && f->dport != dport) {
        return 0;
    }
    if (f->saddr != 0 && f->saddr != saddr) {
        return 0;
    }
    if (f->daddr != 0 && f->daddr != daddr) {
        return 0;
    }
    return 1;
}

static __always_inline void fill_header(struct event_header *h, __u8 kind) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    h->kind = kind;
    h->ts_ns = bpf_ktime_get_ns();
    h->pid = pid_tgid >> 32;
    h->cpu = bpf_get_smp_processor_id();
    bpf_get_current_comm(&h->comm, sizeof(h->comm));
}

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_sys_enter(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_enter_ctx v = {};
    __u64 pid_tgid;

    if (!pass_filter()) {
        return 0;
    }

    pid_tgid = bpf_get_current_pid_tgid();
    v.start_ts_ns = bpf_ktime_get_ns();
    v.syscall_id = (__u32)ctx->id;
    bpf_map_update_elem(&syscall_start, &pid_tgid, &v, BPF_ANY);
    increment_counter(COUNTER_SYS_ENTER);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int trace_sys_exit(struct trace_event_raw_sys_exit *ctx) {
    __u64 pid_tgid;
    __u64 now;
    struct syscall_enter_ctx *v;
    struct syscall_latency_event *event;

    if (!pass_filter()) {
        return 0;
    }

    pid_tgid = bpf_get_current_pid_tgid();
    now = bpf_ktime_get_ns();
    v = bpf_map_lookup_elem(&syscall_start, &pid_tgid);
    if (!v) {
        return 0;
    }

    if (v->syscall_id != 0 && v->syscall_id != 1 && v->syscall_id != 59) {
        bpf_map_delete_elem(&syscall_start, &pid_tgid);
        return 0;
    }

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        increment_counter(COUNTER_RINGBUF_DROPS);
        bpf_map_delete_elem(&syscall_start, &pid_tgid);
        return 0;
    }

    fill_header(&event->h, EVENT_SYSCALL_LATENCY);
    event->syscall_id = v->syscall_id;
    event->latency_ns = now - v->start_ts_ns;
    bpf_ringbuf_submit(event, 0);

    bpf_map_delete_elem(&syscall_start, &pid_tgid);
    increment_counter(COUNTER_SYS_EXIT);
    return 0;
}

SEC("tracepoint/tcp/tcp_retransmit_skb")
int trace_tcp_retransmit(struct trace_event_raw_tcp_event_sk_skb *ctx) {
    struct tcp_retransmit_event *event;
    __u16 family;
    __u16 sport;
    __u16 dport;
    __u32 saddr;
    __u32 daddr;

    if (!pass_filter()) {
        return 0;
    }

    family = BPF_CORE_READ(ctx, family);
    sport = bpf_ntohs(BPF_CORE_READ(ctx, sport));
    dport = bpf_ntohs(BPF_CORE_READ(ctx, dport));
    saddr = BPF_CORE_READ(ctx, saddr);
    daddr = BPF_CORE_READ(ctx, daddr);
    if (!pass_tcp_filter(family, sport, dport, saddr, daddr)) {
        return 0;
    }

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        increment_counter(COUNTER_RINGBUF_DROPS);
        return 0;
    }

    fill_header(&event->h, EVENT_TCP_RETRANSMIT);
    event->family = family;
    event->lport = sport;
    event->dport = dport;
    event->saddr = saddr;
    event->daddr = daddr;
    bpf_ringbuf_submit(event, 0);
    increment_counter(COUNTER_TCP_RETRANS);
    return 0;
}

SEC("kprobe/tcp_rcv_established")
int BPF_KPROBE(trace_tcp_rtt, struct sock *sk) {
    struct tcp_rtt_event *event;
    struct tcp_sock *tp = (struct tcp_sock *)sk;
    __u16 family;
    __u16 sport;
    __u16 dport;
    __u32 saddr;
    __u32 daddr;
    __u32 srtt = 0;

    if (!pass_filter()) {
        return 0;
    }

    family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET) {
        return 0;
    }
    sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    if (!pass_tcp_filter(family, sport, dport, saddr, daddr)) {
        return 0;
    }

    srtt = BPF_CORE_READ(tp, srtt_us);
    if (srtt == 0) {
        return 0;
    }

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        increment_counter(COUNTER_RINGBUF_DROPS);
        return 0;
    }

    fill_header(&event->h, EVENT_TCP_RTT);
    event->family = family;
    event->sport = sport;
    event->dport = dport;
    event->saddr = saddr;
    event->daddr = daddr;
    event->srtt_us = srtt >> 3;
    bpf_ringbuf_submit(event, 0);
    increment_counter(COUNTER_TCP_RTT);
    return 0;
}

SEC("tracepoint/exceptions/page_fault_user")
int trace_page_fault_user(void *ctx) {
    struct page_fault_event *event;

    if (!pass_filter()) {
        return 0;
    }

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        increment_counter(COUNTER_RINGBUF_DROPS);
        return 0;
    }

    fill_header(&event->h, EVENT_PAGE_FAULT);
    event->kernel_fault = 0;
    bpf_ringbuf_submit(event, 0);
    increment_counter(COUNTER_PAGE_FAULT);
    return 0;
}

SEC("tracepoint/exceptions/page_fault_kernel")
int trace_page_fault_kernel(void *ctx) {
    struct page_fault_event *event;

    if (!pass_filter()) {
        return 0;
    }

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        increment_counter(COUNTER_RINGBUF_DROPS);
        return 0;
    }

    fill_header(&event->h, EVENT_PAGE_FAULT);
    event->kernel_fault = 1;
    bpf_ringbuf_submit(event, 0);
    increment_counter(COUNTER_PAGE_FAULT);
    return 0;
}

SEC("tracepoint/sched/sched_wakeup")
int trace_sched_wakeup(struct trace_event_raw_sched_wakeup *ctx) {
    __u64 now;
    __u32 pid;

    if (!pass_filter()) {
        return 0;
    }

    now = bpf_ktime_get_ns();
    pid = (__u32)ctx->pid;
    bpf_map_update_elem(&sched_wakeup_ts, &pid, &now, BPF_ANY);
    increment_counter(COUNTER_SCHED_WAKE);
    return 0;
}

SEC("tracepoint/sched/sched_switch")
int trace_sched_switch(struct trace_event_raw_sched_switch *ctx) {
    __u32 next_pid;
    __u64 *wake_ts;
    struct sched_latency_event *event;

    if (!pass_filter()) {
        return 0;
    }

    next_pid = (__u32)ctx->next_pid;
    wake_ts = bpf_map_lookup_elem(&sched_wakeup_ts, &next_pid);
    if (!wake_ts) {
        return 0;
    }

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        increment_counter(COUNTER_RINGBUF_DROPS);
        bpf_map_delete_elem(&sched_wakeup_ts, &next_pid);
        return 0;
    }

    fill_header(&event->h, EVENT_SCHED_LATENCY);
    event->prev_pid = (__u32)ctx->prev_pid;
    event->next_pid = next_pid;
    event->runq_latency_ns = bpf_ktime_get_ns() - *wake_ts;
    bpf_ringbuf_submit(event, 0);
    bpf_map_delete_elem(&sched_wakeup_ts, &next_pid);
    increment_counter(COUNTER_SCHED_SWITCH);
    return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int trace_sched_exec(struct trace_event_raw_sched_process_exec *ctx) {
    struct exec_event *event;

    if (!pass_filter()) {
        return 0;
    }

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        increment_counter(COUNTER_RINGBUF_DROPS);
        return 0;
    }

    fill_header(&event->h, EVENT_EXEC);
    bpf_core_read_str(&event->filename, sizeof(event->filename), BPF_CORE_READ(ctx, filename));
    bpf_ringbuf_submit(event, 0);
    increment_counter(COUNTER_EXEC);
    return 0;
}

SEC("uprobe/kernelpulse_user_probe")
int trace_user_probe(struct pt_regs *ctx) {
    increment_counter(COUNTER_EXEC);
    return 0;
}
