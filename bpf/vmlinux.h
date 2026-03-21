#ifndef __KERNELPULSE_VMLINUX_H__
#define __KERNELPULSE_VMLINUX_H__

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed long long __s64;
typedef signed int __s32;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;

struct pt_regs {
    __u64 r15;
    __u64 r14;
    __u64 r13;
    __u64 r12;
    __u64 bp;
    __u64 bx;
    __u64 r11;
    __u64 r10;
    __u64 r9;
    __u64 r8;
    __u64 ax;
    __u64 cx;
    __u64 dx;
    __u64 si;
    __u64 di;
    __u64 orig_ax;
    __u64 ip;
    __u64 cs;
    __u64 flags;
    __u64 sp;
    __u64 ss;
    __u64 rdi;
    __u64 rsi;
    __u64 rdx;
    __u64 rcx;
};

struct in6_addr {
    __u32 in6_u_u6_addr32[4];
};

struct sock_common {
    __u16 skc_family;
    __u16 skc_state;
    __u32 skc_rcv_saddr;
    __u32 skc_daddr;
    __u16 skc_num;
    __u16 skc_dport;
    struct in6_addr skc_v6_rcv_saddr;
    struct in6_addr skc_v6_daddr;
};

struct sock {
    struct sock_common __sk_common;
};

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
    __u32 saddr;
    __u32 daddr;
    __u32 saddr_v6[4];
    __u32 daddr_v6[4];
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

struct trace_event_raw_sched_process_exec {
    __u64 unused;
    const char *filename;
};

#endif
