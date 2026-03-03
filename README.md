# kernelpulse

[![build](https://github.com/mozaika228/kernelpulse/actions/workflows/ci.yml/badge.svg)](https://github.com/mozaika228/kernelpulse/actions/workflows/ci.yml)
[![license](https://img.shields.io/github/license/mozaika228/kernelpulse)](./LICENSE)

Production-oriented eBPF kernel observability toolkit for Linux.

`kernelpulse` tracks hot kernel paths in real time with low overhead and exports both operator-friendly console output and machine-friendly telemetry.

## Why kernelpulse

`strace` and `perf` are great tools, but they solve different classes of problems.

- vs `strace`:
  - `strace` is ptrace-based and process-scoped.
  - `kernelpulse` runs in-kernel with eBPF and scales to system-wide tracing with lower overhead.
- vs `perf`:
  - `perf` is powerful for profiling and sampling.
  - `kernelpulse` is event-oriented with structured domain metrics (latency, retransmits, drops, run-queue delays) and direct JSON/Prometheus outputs.

## What it tracks

- Syscall latency for `read/write/execve`
- TCP retransmits
- TCP RTT sampling (kprobe path)
- Page faults (user/kernel)
- Scheduler run-queue latency (`sched_wakeup` -> `sched_switch`)
- Exec monitoring (`sched_process_exec`)

## Features

- `tracepoint` probes
- `kprobe` probes
- `uprobe` support (optional user-space symbol attach)
- Ring buffer transport (`BPF_MAP_TYPE_RINGBUF`)
- Per-CPU counters (`BPF_MAP_TYPE_PERCPU_ARRAY`)
- Runtime filtering:
  - `-p` PID filter
  - `-c` COMM filter
- Reporting and exports:
  - top-N slow syscalls (`-t`)
  - JSON snapshots (`-o output.json`)
  - ASCII heatmap in console
  - Prometheus metrics endpoint
- CO-RE pipeline:
  - BTF + `vmlinux.h`
  - `bpf2go` object generation
  - `bpf_core_read` usage in RTT path

## Build & Run

Requirements:

- Linux with BTF enabled (`/sys/kernel/btf/vmlinux`)
- `clang`, `bpftool`, `make`
- Go 1.22+
- root privileges / required capabilities

```bash
make deps
make generate
make build
sudo ./kernelpulse -interval 5s
```

Or:

```bash
make run
```

## Command examples

Only one process:

```bash
sudo ./kernelpulse -p 1234
```

Only one process name:

```bash
sudo ./kernelpulse -c nginx
```

Top 10 slowest syscall groups + JSON export:

```bash
sudo ./kernelpulse -t 10 -o /tmp/kernelpulse.json
```

Enable Prometheus endpoint on a custom port:

```bash
sudo ./kernelpulse -prom-addr :22112
```

Attach optional uprobe:

```bash
sudo ./kernelpulse -uprobe-bin /usr/local/bin/myapp -uprobe-sym main.main
```

## Metrics for Grafana

Prometheus metrics:

- `kernelpulse_events_per_sec`
- `kernelpulse_syscall_latency_p99_ms`
- `kernelpulse_error_rate`

Start the dashboard stack:

```bash
cd observability
docker compose up -d
```

- Prometheus: `http://localhost:9090`
- Grafana: `http://localhost:3000` (`admin/admin`)

## CI

GitHub Actions workflow:

- installs clang/bpftool/toolchain
- generates BPF objects (`make generate`)
- builds Go binary
- runs unit tests
- runs privileged load test (`make test-load`) to verify BPF objects can be loaded

## Tests and fault tolerance

- `internal/ebpf/load_test.go`: validates BPF object load path
- `scripts/bpf-selftest.sh`: `bpftool` load self-check with verifier log extraction
- ring buffer reserve failures tracked and surfaced as `error_rate`
- verifier-failure hints surfaced at startup for common reject categories

## CO-RE notes

- Repository ships with `bpf/vmlinux.h` for reproducible CI builds
- You can refresh it locally from target kernel BTF when needed:
  - `bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h`
- CO-RE-compatible field access in kernel-dependent paths
- Build once, run on multiple compatible kernels

## Documentation

- [Architecture](./docs/ARCHITECTURE.md)
- [Verifier](./docs/VERIFIER.md)
- [Quick Reference](./docs/QUICK_REFERENCE.md)

## Install

As binary:

```bash
go install github.com/mozaika228/kernelpulse/cmd/kernelpulse@latest
```

As container image:

```bash
docker build -t kernelpulse:latest .
```

Run container in privileged mode with host kernel interfaces mounted.
