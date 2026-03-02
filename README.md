# kernelpulse

`kernelpulse` is an eBPF-based Linux kernel observability tool in the spirit of `bpftrace`, with a structured data pipeline:

- eBPF probes in C (`tracepoints`).
- Low-overhead event delivery via ring buffer.
- Per-CPU counters in kernel space.
- Userspace aggregation and latency heatmap-friendly buckets in Go.

## Current probes

- `raw_syscalls/sys_enter` and `raw_syscalls/sys_exit`
  - captures syscall latency
- `tcp/tcp_retransmit_skb`
  - counts TCP retransmit signals

## Architecture

1. `bpf/kernelpulse.bpf.c`
2. `internal/ebpf/gen.go` (`bpf2go` CO-RE flow)
3. `cmd/kernelpulse/main.go`
4. `internal/collector/collector.go`

The BPF side keeps:

- `syscall_start` hash map: start timestamp by `pid_tgid`
- `events` ring buffer: syscall and TCP retransmit events
- `counters` per-CPU array: ingress/egress telemetry and reserve failures

Userspace side:

- attaches tracepoints
- streams ring buffer events
- aggregates into report snapshots and latency buckets (`<1us` .. `>=10ms`)

## Requirements

- Linux kernel with BTF enabled (for CO-RE)
- `clang`
- `bpftool`
- Go 1.22+
- root privileges (`CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_ADMIN` depending on distro/kernel)

## Build / Run

```bash
make generate
make build
sudo ./kernelpulse -interval 5s
```

Or:

```bash
make run
```

## Notes on verifier and safety

- No unbounded loops in BPF programs.
- Fixed-size events for predictable verifier behavior.
- Early return on failed ringbuf reserve with dedicated failure counter.
- Kernel-side maps are bounded.

## Next steps

- Add `kprobe`/`kretprobe` for syscall-family specific deep metrics.
- Add `uprobe` support for application-level latency correlation.
- Add tail-call program array pipelines for high-cardinality workloads.
- Add Prometheus/OpenTelemetry exporters.
