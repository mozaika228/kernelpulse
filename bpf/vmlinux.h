#ifndef __KERNELPULSE_VMLINUX_H__
#define __KERNELPULSE_VMLINUX_H__

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed int __s32;

struct pt_regs {};

struct sock {};

struct tcp_sock {
    __u32 srtt_us;
};

struct trace_event_raw_sys_enter {
    __u64 unused;
    long id;
};

struct trace_event_raw_sys_exit {
    __u64 unused;
    long id;
};

struct trace_event_raw_tcp_event_sk_skb {
    __u16 family;
    __u16 sport;
    __u16 dport;
    __u16 _pad;
};

struct trace_event_raw_sched_wakeup {
    __u64 unused;
    int pid;
};

struct trace_event_raw_sched_switch {
    __u64 unused;
    int prev_pid;
    int next_pid;
};

#endif
