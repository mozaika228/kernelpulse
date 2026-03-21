package collector

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
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
	SaddrV6 [4]uint32
	DaddrV6 [4]uint32
}

type TCPRTTEvent struct {
	Header
	Family uint16
	Sport  uint16
	Dport  uint16
	_      uint16
	Saddr  uint32
	Daddr  uint32
	SaddrV6 [4]uint32
	DaddrV6 [4]uint32
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
	TopTCPTuples   []TCPTupleTop     `json:"top_tcp_tuples"`
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

type execAgg struct {
	count uint64
}

type ExecTop struct {
	Filename string `json:"filename"`
	Count    uint64 `json:"count"`
}

type TCPTuple struct {
	Family  uint16
	Sport   uint16
	Dport   uint16
	Saddr4  uint32
	Daddr4  uint32
	Saddr6  [16]byte
	Daddr6  [16]byte
}

type tcpAgg struct {
	retrans uint64
	rttHist *hdrhistogram.Histogram
}

type TCPTupleTop struct {
	Family     string  `json:"family"`
	Saddr      string  `json:"saddr"`
	Daddr      string  `json:"daddr"`
	Sport      uint16  `json:"sport"`
	Dport      uint16  `json:"dport"`
	Retransmit uint64  `json:"retransmits"`
	RTTP99     float64 `json:"rtt_p99_ms"`
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
	execAgg        map[string]*execAgg
	tcpAgg         map[TCPTuple]*tcpAgg

	topCommsOverride []CommTop

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
		execAgg:        map[string]*execAgg{},
		tcpAgg:         map[TCPTuple]*tcpAgg{},
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
		TopTCPTuples:   a.topTCPTuples(topN),
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
	clear(a.execAgg)
	clear(a.tcpAgg)
	a.topCommsOverride = nil
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

	return nil
}

func (a *Aggregator) observeTCPRetransmit(raw []byte) error {
	var e TCPRetransmitEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &e); err != nil {
		return fmt.Errorf("decode tcp retransmit event: %w", err)
	}
	a.mu.Lock()
	a.tcpRetransmits++
	if len(a.tcpAgg) < 2048 {
		key := tupleFromRetransmit(e)
		agg := a.tcpAgg[key]
		if agg == nil {
			agg = &tcpAgg{rttHist: hdrhistogram.New(1, 30_000_000, 3)}
			a.tcpAgg[key] = agg
		}
		agg.retrans++
	}
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
	if len(a.tcpAgg) < 2048 {
		key := tupleFromRTT(e)
		agg := a.tcpAgg[key]
		if agg == nil {
			agg = &tcpAgg{rttHist: hdrhistogram.New(1, 30_000_000, 3)}
			a.tcpAgg[key] = agg
		}
		_ = agg.rttHist.RecordValue(int64(maxU64(1, uint64(e.SRTTus))))
	}
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

func (a *Aggregator) SetTopComms(top []CommTop) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.topCommsOverride = top
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
	if a.topCommsOverride != nil {
		return a.topCommsOverride
	}
	return nil
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

func (a *Aggregator) topTCPTuples(topN int) []TCPTupleTop {
	out := make([]TCPTupleTop, 0, len(a.tcpAgg))
	for tuple, agg := range a.tcpAgg {
		p99 := 0.0
		if agg.rttHist != nil && agg.rttHist.TotalCount() > 0 {
			p99 = float64(agg.rttHist.ValueAtQuantile(99.0)) / 1000
		}
		saddr, daddr, fam := formatTuple(tuple)
		out = append(out, TCPTupleTop{
			Family:     fam,
			Saddr:      saddr,
			Daddr:      daddr,
			Sport:      tuple.Sport,
			Dport:      tuple.Dport,
			Retransmit: agg.retrans,
			RTTP99:     p99,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Retransmit == out[j].Retransmit {
			return out[i].RTTP99 > out[j].RTTP99
		}
		return out[i].Retransmit > out[j].Retransmit
	})
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

func tupleFromRetransmit(e TCPRetransmitEvent) TCPTuple {
	t := TCPTuple{
		Family: e.Family,
		Sport:  e.LPort,
		Dport:  e.DPort,
		Saddr4: e.Saddr,
		Daddr4: e.Daddr,
	}
	if e.Family == 10 {
		copy(t.Saddr6[:], v6ToBytes(e.SaddrV6))
		copy(t.Daddr6[:], v6ToBytes(e.DaddrV6))
	}
	return t
}

func tupleFromRTT(e TCPRTTEvent) TCPTuple {
	t := TCPTuple{
		Family: e.Family,
		Sport:  e.Sport,
		Dport:  e.Dport,
		Saddr4: e.Saddr,
		Daddr4: e.Daddr,
	}
	if e.Family == 10 {
		copy(t.Saddr6[:], v6ToBytes(e.SaddrV6))
		copy(t.Daddr6[:], v6ToBytes(e.DaddrV6))
	}
	return t
}

func v6ToBytes(v [4]uint32) [16]byte {
	var out [16]byte
	out[0] = byte(v[0] >> 24)
	out[1] = byte(v[0] >> 16)
	out[2] = byte(v[0] >> 8)
	out[3] = byte(v[0])
	out[4] = byte(v[1] >> 24)
	out[5] = byte(v[1] >> 16)
	out[6] = byte(v[1] >> 8)
	out[7] = byte(v[1])
	out[8] = byte(v[2] >> 24)
	out[9] = byte(v[2] >> 16)
	out[10] = byte(v[2] >> 8)
	out[11] = byte(v[2])
	out[12] = byte(v[3] >> 24)
	out[13] = byte(v[3] >> 16)
	out[14] = byte(v[3] >> 8)
	out[15] = byte(v[3])
	return out
}

func formatTuple(t TCPTuple) (string, string, string) {
	if t.Family == 10 {
		s := netip.AddrFrom16(t.Saddr6).String()
		d := netip.AddrFrom16(t.Daddr6).String()
		return s, d, "ipv6"
	}
	s := netip.AddrFrom4(u32ToV4(t.Saddr4)).String()
	d := netip.AddrFrom4(u32ToV4(t.Daddr4)).String()
	return s, d, "ipv4"
}

func u32ToV4(v uint32) [4]byte {
	return [4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
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
