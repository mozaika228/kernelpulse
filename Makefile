BPF_SRC := bpf/kernelpulse.bpf.c
VMLINUX := bpf/vmlinux.h

.PHONY: deps generate build run test test-load test-bpf docker-build clean

deps:
	go mod tidy

generate:
	go generate ./internal/ebpf

build:
	go build ./cmd/kernelpulse

run:
	sudo go run ./cmd/kernelpulse -interval 5s -prom-addr :2112

test:
	go test ./...

test-load:
	sudo -E go test ./internal/ebpf -run TestBPFLoad -v

test-bpf:
	bash ./scripts/bpf-selftest.sh

docker-build:
	docker build -t kernelpulse:latest .

clean:
	rm -f internal/ebpf/kernelpulse_bpfel.go internal/ebpf/kernelpulse_bpfel.o coverage.out
