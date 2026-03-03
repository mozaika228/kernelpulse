package ebpf

//go:generate go run -mod=mod github.com/cilium/ebpf/cmd/bpf2go@v0.15.0 -target bpfel -cc clang -cflags "-O2 -g -D__TARGET_ARCH_x86" kernelpulse ../../bpf/kernelpulse.bpf.c -- -I../../bpf
