package collector

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

type EventKind uint8

const (
	EventSyscall EventKind = iota + 1
	EventTCPRetransmit
)

type SyscallEvent struct {
	Kind      uint8
	_         [3]byte
	TSNs      uint64
	PID       uint32
	CPU       uint32
	ID        uint32
	LatencyNs uint64
	Comm      [16]byte
}

type TCPRetransmitEvent struct {
	Kind   uint8
	_      [3]byte
	TSNs   uint64
	PID    uint32
	CPU    uint32
	Family uint16
	LPort  uint16
	DPort  uint16
	Pad16  uint16
	Comm   [16]byte
}

type Snapshot struct {
	WindowStart      time.Time
	WindowEnd        time.Time
	SyscallCount     uint64
	TCPRetransmits   uint64
	RingbufDrops     uint64
	SyscallLatencyNS map[string]uint64
}

type Aggregator struct {
	mu sync.Mutex

	windowStart time.Time

	syscalls      uint64
	retransmits   uint64
	ringbufDrops  uint64
	syscallBucket map[string]uint64
}

func NewAggregator() *Aggregator {
	return &Aggregator{
		windowStart:   time.Now(),
		syscallBucket: make(map[string]uint64),
	}
}

func (a *Aggregator) ObserveSyscall(raw []byte) error {
	var e SyscallEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &e); err != nil {
		return fmt.Errorf("decode syscall event: %w", err)
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	a.syscalls++
	a.syscallBucket[latencyBucket(e.LatencyNs)]++
	return nil
}

func (a *Aggregator) ObserveTCPRetransmit(raw []byte) error {
	var e TCPRetransmitEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &e); err != nil {
		return fmt.Errorf("decode tcp retransmit event: %w", err)
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	a.retransmits++
	return nil
}

func (a *Aggregator) ObserveRingbufDrops(drops uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.ringbufDrops += drops
}

func (a *Aggregator) SnapshotAndReset() Snapshot {
	a.mu.Lock()
	defer a.mu.Unlock()

	s := Snapshot{
		WindowStart:      a.windowStart,
		WindowEnd:        time.Now(),
		SyscallCount:     a.syscalls,
		TCPRetransmits:   a.retransmits,
		RingbufDrops:     a.ringbufDrops,
		SyscallLatencyNS: make(map[string]uint64, len(a.syscallBucket)),
	}

	for k, v := range a.syscallBucket {
		s.SyscallLatencyNS[k] = v
	}

	a.windowStart = time.Now()
	a.syscalls = 0
	a.retransmits = 0
	a.ringbufDrops = 0
	clear(a.syscallBucket)

	return s
}

func latencyBucket(ns uint64) string {
	us := ns / 1000
	switch {
	case us < 1:
		return "<1us"
	case us < 5:
		return "1-5us"
	case us < 10:
		return "5-10us"
	case us < 50:
		return "10-50us"
	case us < 100:
		return "50-100us"
	case us < 500:
		return "100-500us"
	case us < 1_000:
		return "0.5-1ms"
	case us < 5_000:
		return "1-5ms"
	case us < 10_000:
		return "5-10ms"
	default:
		return ">=10ms"
	}
}
