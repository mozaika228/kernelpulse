BPF_SRC := bpf/kernelpulse.bpf.c
VMLINUX := bpf/vmlinux.h

.PHONY: generate build run clean

generate:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)
	go generate ./internal/ebpf

build:
	go build ./cmd/kernelpulse

run:
	sudo go run ./cmd/kernelpulse -interval 5s

clean:
	rm -f internal/ebpf/kernelpulse_bpfel.go internal/ebpf/kernelpulse_bpfel.o
