//go:build linux

package ebpf

import (
	"os"
	"testing"

	"github.com/cilium/ebpf/rlimit"
)

func TestBPFLoad(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root privileges to load eBPF programs")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock: %v", err)
	}

	var objs KernelpulseObjects
	if err := LoadKernelpulseObjects(&objs, nil); err != nil {
		t.Fatalf("load eBPF objects: %v", err)
	}
	defer objs.Close()
}
