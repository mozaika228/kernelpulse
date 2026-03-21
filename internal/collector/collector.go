package collector

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/HdrHistogram/hdrhistogram-go"
)

type EventKind uint8

const (
	EventSyscallLatency EventKind = 1
	EventTCPRetransmit  EventKind = 2
	EventTCPRTT         EventKind = 3
	EventPageFault      EventKind = 4
	EventSchedLatency   EventKind = 5
	EventExec           EventKind = 6
)

type Header struct {
	Kind uint8
	_    [3]byte
	TSNs uint64
	PID  uint32
	CPU  uint32
	Comm [16]byte
}

type SyscallLatencyEvent struct {
	Header
	SyscallID uint32
	_         uint32
	LatencyNs uint64
}

type TCPRetransmitEvent struct {
	Header
	Family uint16
	LPort  uint16
	DPort  uint16
	_      uint16
	Saddr  uint32
	Daddr  uint32
}

type TCPRTTEvent struct {
	Header
	Family uint16
	Sport  uint16
	Dport  uint16
	_      uint16
	Saddr  uint32
	Daddr  uint32
	SRTTus uint32
	_      [4]byte
}

type PageFaultEvent struct {
	Header
	KernelFault uint8
	_           [7]byte
}

type SchedLatencyEvent struct {
	Header
	PrevPID      uint32
	NextPID      uint32
	RunQLatencyN uint64
}

type ExecEvent struct {
	Header
	Filename [64]byte
}

type SyscallTop struct {
	Syscall   string  `json:"syscall"`
	Count     uint64  `json:"count"`
	MaxLatencyMS float64 `json:"max_latency_ms"`
	AvgLatencyMS float64 `json:"avg_latency_ms"`
}

type ProcTop struct {
	PID          uint32  `json:"pid"`
	Comm         string  `json:"comm"`
	Count        uint64  `json:"count"`
	MaxLatencyMS float64 `json:"max_latency_ms"`
	AvgLatencyMS float64 `json:"avg_latency_ms"`
}

type CommTop struct {
	Comm         string  `json:"comm"`
	Count        uint64  `json:"count"`
	P99          float64 `json:"p99"`
	MaxLatencyMS float64 `json:"max_latency_ms"`
	AvgLatencyMS float64 `json:"avg_latency_ms"`
}

type Percentiles struct {
	P50 float64 `json:"p50"`
	P95 float64 `json:"p95"`
	P99 float64 `json:"p99"`
}

type Snapshot struct {
	WindowStart time.Time `json:"window_start"`
	WindowEnd   time.Time `json:"window_end"`
	WindowSec   float64   `json:"window_sec"`

	Syscalls       uint64 `json:"syscalls"`
	TCPRetransmits uint64 `json:"tcp_retransmits"`
	PageFaults     uint64 `json:"page_faults"`
	SchedEvents    uint64 `json:"sched_events"`
	ExecEvents     uint64 `json:"exec_events"`
	RingbufDrops   uint64 `json:"ringbuf_drops"`

	EventsPerSec float64 `json:"events_per_sec"`
	ErrorRate    float64 `json:"error_rate"`

	SyscallLatency Percentiles `json:"syscall_latency_ms"`
	TCPRTT         Percentiles `json:"tcp_rtt_ms"`
	RunQLatency    Percentiles `json:"runq_latency_ms"`

	SyscallHeatmap map[string]uint64 `json:"syscall_heatmap"`
	TopSyscalls    []SyscallTop      `json:"top_syscalls"`
	TopProcesses   []ProcTop         `json:"top_processes"`
	TopComms       []CommTop         `json:"top_comms"`
	TopExecs       []ExecTop         `json:"top_execs"`
}

type syscallAgg struct {
	count uint64
	total uint64
	max   uint64
}

type procAgg struct {
	comm  string
	count uint64
	total uint64
	max   uint64
}

type commAgg struct {
	count uint64
	total uint64
	max   uint64
	hist  *hdrhistogram.Histogram
}

type execAgg struct {
	count uint64
}

type ExecTop struct {
	Filename string `json:"filename"`
	Count    uint64 `json:"count"`
}

type Aggregator struct {
	mu sync.Mutex

	windowStart time.Time

	syscalls       uint64
	tcpRetransmits uint64
	pageFaults     uint64
	schedEvents    uint64
	execEvents     uint64
	ringbufDrops   uint64

	syscallHeatmap map[string]uint64
	syscallAgg     map[uint32]*syscallAgg
	procAgg        map[uint32]*procAgg
	commAgg        map[string]*commAgg
	execAgg        map[string]*execAgg

	syscallHist *hdrhistogram.Histogram
	tcpRTTHist  *hdrhistogram.Histogram
	runQHist    *hdrhistogram.Histogram
}

func NewAggregator() *Aggregator {
	return &Aggregator{
		windowStart:    time.Now(),
		syscallHeatmap: map[string]uint64{},
		syscallAgg:     map[uint32]*syscallAgg{},
		procAgg:        map[uint32]*procAgg{},
		commAgg:        map[string]*commAgg{},
		execAgg:        map[string]*execAgg{},
		syscallHist:    hdrhistogram.New(1, 60_000_000, 3), // us
		tcpRTTHist:     hdrhistogram.New(1, 30_000_000, 3), // us
		runQHist:       hdrhistogram.New(1, 30_000_000, 3), // us
	}
}

func (a *Aggregator) Observe(raw []byte) error {
	if len(raw) == 0 {
		return nil
	}
	switch EventKind(raw[0]) {
	case EventSyscallLatency:
		return a.observeSyscall(raw)
	case EventTCPRetransmit:
		return a.observeTCPRetransmit(raw)
	case EventTCPRTT:
		return a.observeTCPRTT(raw)
	case EventPageFault:
		return a.observePageFault(raw)
	case EventSchedLatency:
		return a.observeSched(raw)
	case EventExec:
		return a.observeExec(raw)
	default:
		return nil
	}
}

func (a *Aggregator) ObserveRingbufDrops(drops uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.ringbufDrops += drops
}

func (a *Aggregator) SnapshotAndReset(topN int) Snapshot {
	a.mu.Lock()
	defer a.mu.Unlock()

	end := time.Now()
	windowSec := end.Sub(a.windowStart).Seconds()
	if windowSec <= 0 {
		windowSec = 1
	}
	totalEvents := a.syscalls + a.tcpRetransmits + a.pageFaults + a.schedEvents + a.execEvents
	errorRate := 0.0
	if totalEvents > 0 {
		errorRate = float64(a.ringbufDrops) / float64(totalEvents+a.ringbufDrops)
	}

	s := Snapshot{
		WindowStart:    a.windowStart,
		WindowEnd:      end,
		WindowSec:      windowSec,
		Syscalls:       a.syscalls,
		TCPRetransmits: a.tcpRetransmits,
		PageFaults:     a.pageFaults,
		SchedEvents:    a.schedEvents,
		ExecEvents:     a.execEvents,
		RingbufDrops:   a.ringbufDrops,
		EventsPerSec:   float64(totalEvents) / windowSec,
		ErrorRate:      errorRate,
		SyscallLatency: percentileMS(a.syscallHist),
		TCPRTT:         percentileMS(a.tcpRTTHist),
		RunQLatency:    percentileMS(a.runQHist),
		SyscallHeatmap: cloneMap(a.syscallHeatmap),
		TopSyscalls:    a.topSyscalls(topN),
		TopProcesses:   a.topProcesses(topN),
		TopComms:       a.topComms(topN),
		TopExecs:       a.topExecs(topN),
	}

	a.windowStart = end
	a.syscalls = 0
	a.tcpRetransmits = 0
	a.pageFaults = 0
	a.schedEvents = 0
	a.execEvents = 0
	a.ringbufDrops = 0
	clear(a.syscallHeatmap)
	clear(a.syscallAgg)
	clear(a.procAgg)
	clear(a.commAgg)
	clear(a.execAgg)
	a.syscallHist.Reset()
	a.tcpRTTHist.Reset()
	a.runQHist.Reset()
	return s
}

func (a *Aggregator) observeSyscall(raw []byte) error {
	var e SyscallLatencyEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &e); err != nil {
		return fmt.Errorf("decode syscall event: %w", err)
	}
	us := nsToUS(e.LatencyNs)

	a.mu.Lock()
	defer a.mu.Unlock()
	a.syscalls++
	a.syscallHeatmap[latencyBucket(us)]++
	_ = a.syscallHist.RecordValue(int64(us))

	agg := a.syscallAgg[e.SyscallID]
	if agg == nil {
		agg = &syscallAgg{}
		a.syscallAgg[e.SyscallID] = agg
	}
	agg.count++
	agg.total += e.LatencyNs
	if e.LatencyNs > agg.max {
		agg.max = e.LatencyNs
	}

	pagg := a.procAgg[e.PID]
	if pagg == nil {
		pagg = &procAgg{comm: commString(e.Comm)}
		a.procAgg[e.PID] = pagg
	}
	pagg.count++
	pagg.total += e.LatencyNs
	if e.LatencyNs > pagg.max {
		pagg.max = e.LatencyNs
	}

	comm := commString(e.Comm)
	if comm != "" {
		cagg := a.commAgg[comm]
		if cagg == nil {
			if len(a.commAgg) < 256 {
				cagg = &commAgg{hist: hdrhistogram.New(1, 60_000_000, 3)}
				a.commAgg[comm] = cagg
			}
		}
		if cagg != nil {
			cagg.count++
			cagg.total += e.LatencyNs
			if e.LatencyNs > cagg.max {
				cagg.max = e.LatencyNs
			}
			_ = cagg.hist.RecordValue(int64(us))
		}
	}
	return nil
}

func (a *Aggregator) observeTCPRetransmit(raw []byte) error {
	var e TCPRetransmitEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &e); err != nil {
		return fmt.Errorf("decode tcp retransmit event: %w", err)
	}
	a.mu.Lock()
	a.tcpRetransmits++
	a.mu.Unlock()
	return nil
}

func (a *Aggregator) observeTCPRTT(raw []byte) error {
	var e TCPRTTEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &e); err != nil {
		return fmt.Errorf("decode tcp rtt event: %w", err)
	}
	a.mu.Lock()
	_ = a.tcpRTTHist.RecordValue(int64(maxU64(1, uint64(e.SRTTus))))
	a.mu.Unlock()
	return nil
}

func (a *Aggregator) observePageFault(raw []byte) error {
	var e PageFaultEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &e); err != nil {
		return fmt.Errorf("decode page fault event: %w", err)
	}
	a.mu.Lock()
	a.pageFaults++
	a.mu.Unlock()
	return nil
}

func (a *Aggregator) observeSched(raw []byte) error {
	var e SchedLatencyEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &e); err != nil {
		return fmt.Errorf("decode sched event: %w", err)
	}
	a.mu.Lock()
	a.schedEvents++
	_ = a.runQHist.RecordValue(int64(nsToUS(e.RunQLatencyN)))
	a.mu.Unlock()
	return nil
}

func (a *Aggregator) observeExec(raw []byte) error {
	var e ExecEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &e); err != nil {
		return fmt.Errorf("decode exec event: %w", err)
	}
	a.mu.Lock()
	a.execEvents++
	name := strings.TrimRight(string(e.Filename[:]), "\x00")
	if name != "" {
		agg := a.execAgg[name]
		if agg == nil {
			agg = &execAgg{}
			a.execAgg[name] = agg
		}
		agg.count++
	}
	a.mu.Unlock()
	return nil
}

func (a *Aggregator) topSyscalls(topN int) []SyscallTop {
	out := make([]SyscallTop, 0, len(a.syscallAgg))
	for id, agg := range a.syscallAgg {
		if agg.count == 0 {
			continue
		}
		out = append(out, SyscallTop{
			Syscall:      syscallName(id),
			Count:        agg.count,
			MaxLatencyMS: float64(agg.max) / 1_000_000,
			AvgLatencyMS: float64(agg.total) / float64(agg.count) / 1_000_000,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MaxLatencyMS > out[j].MaxLatencyMS })
	if topN > 0 && len(out) > topN {
		return out[:topN]
	}
	return out
}

func (a *Aggregator) topProcesses(topN int) []ProcTop {
	out := make([]ProcTop, 0, len(a.procAgg))
	for pid, agg := range a.procAgg {
		if agg.count == 0 {
			continue
		}
		out = append(out, ProcTop{
			PID:          pid,
			Comm:         agg.comm,
			Count:        agg.count,
			MaxLatencyMS: float64(agg.max) / 1_000_000,
			AvgLatencyMS: float64(agg.total) / float64(agg.count) / 1_000_000,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MaxLatencyMS > out[j].MaxLatencyMS })
	if topN > 0 && len(out) > topN {
		return out[:topN]
	}
	return out
}

func (a *Aggregator) topComms(topN int) []CommTop {
	out := make([]CommTop, 0, len(a.commAgg))
	for comm, agg := range a.commAgg {
		if agg.count == 0 {
			continue
		}
		p99 := 0.0
		if agg.hist != nil && agg.hist.TotalCount() > 0 {
			p99 = float64(agg.hist.ValueAtQuantile(99.0)) / 1000
		}
		out = append(out, CommTop{
			Comm:         comm,
			Count:        agg.count,
			P99:          p99,
			MaxLatencyMS: float64(agg.max) / 1_000_000,
			AvgLatencyMS: float64(agg.total) / float64(agg.count) / 1_000_000,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].P99 > out[j].P99 })
	if topN > 0 && len(out) > topN {
		return out[:topN]
	}
	return out
}

func (a *Aggregator) topExecs(topN int) []ExecTop {
	out := make([]ExecTop, 0, len(a.execAgg))
	for name, agg := range a.execAgg {
		out = append(out, ExecTop{Filename: name, Count: agg.count})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	if topN > 0 && len(out) > topN {
		return out[:topN]
	}
	return out
}

func ASCIIHeatmap(m map[string]uint64) string {
	buckets := []string{"<1us", "1-5us", "5-10us", "10-50us", "50-100us", "100-500us", "0.5-1ms", "1-5ms", "5-10ms", ">=10ms"}
	var sb strings.Builder
	for _, k := range buckets {
		v := m[k]
		barN := int(v)
		if barN > 48 {
			barN = 48
		}
		sb.WriteString(fmt.Sprintf("  %-8s %6d %s\n", k, v, strings.Repeat("#", barN)))
	}
	return sb.String()
}

func percentileMS(h *hdrhistogram.Histogram) Percentiles {
	if h.TotalCount() == 0 {
		return Percentiles{}
	}
	return Percentiles{
		P50: float64(h.ValueAtQuantile(50.0)) / 1000,
		P95: float64(h.ValueAtQuantile(95.0)) / 1000,
		P99: float64(h.ValueAtQuantile(99.0)) / 1000,
	}
}

func latencyBucket(us uint64) string {
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
	case us < 1000:
		return "0.5-1ms"
	case us < 5000:
		return "1-5ms"
	case us < 10000:
		return "5-10ms"
	default:
		return ">=10ms"
	}
}

func syscallName(id uint32) string {
	switch id {
	case 0:
		return "read"
	case 1:
		return "write"
	case 59:
		return "execve"
	default:
		return fmt.Sprintf("sys_%d", id)
	}
}

func commString(raw [16]byte) string {
	s := string(raw[:])
	return strings.TrimRight(s, "\x00")
}

func cloneMap(in map[string]uint64) map[string]uint64 {
	out := make(map[string]uint64, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func nsToUS(ns uint64) uint64 {
	return maxU64(1, ns/1000)
}

func maxU64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}
