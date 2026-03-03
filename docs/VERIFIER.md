# How Verifier Works

eBPF verifier performs static analysis before load:

- Control-flow safety: no unbounded loops.
- Memory safety: stack/map/context access bounds.
- Type and pointer tracking.
- Helper-call contract checks.

If verification fails, program load is rejected before attach.

## Typical reject classes

- `invalid bpf_context access`
- `R? invalid mem access`
- `stack depth exceeds limit`
- unbounded or unsupported loop logic

## Debugging

1. Try loading with `bpftool` and `--debug`.
2. Dump JIT / xlated instructions:
   - `sudo bpftool prog show`
   - `sudo bpftool prog dump xlated id <ID>`
3. Validate BTF/CO-RE assumptions:
   - `sudo bpftool btf dump file /sys/kernel/btf/vmlinux | less`
4. Keep stack usage small and event structs fixed-size.
5. Correlate userspace behavior with `gdb`:
   - `sudo gdb --args ./kernelpulse -interval 2s`
   - set breakpoints in userspace decode/aggregation paths.
