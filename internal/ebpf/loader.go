//go:build linux

package ebpf

import "github.com/cilium/ebpf"

type KernelpulseObjects = kernelpulseObjects

func LoadKernelpulseObjects(obj *KernelpulseObjects, opts *ebpf.CollectionOptions) error {
	return loadKernelpulseObjects(obj, opts)
}
