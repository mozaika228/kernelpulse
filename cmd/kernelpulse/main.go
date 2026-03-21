//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/mozaika228/kernelpulse/internal/collector"
	kebpf "github.com/mozaika228/kernelpulse/internal/ebpf"
)

type filterConfig struct {
	PID     uint32
	Comm    [16]byte
	CommSet uint8
	_       [3]byte
}

var (
	metricEventsPerSec = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kernelpulse_events_per_sec",
		Help: "Processed events per second in the reporting window.",
	})
	metricLatencyP99MS = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kernelpulse_syscall_latency_p99_ms",
		Help: "P99 syscall latency in milliseconds.",
	})
	metricErrorRate = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kernelpulse_error_rate",
		Help: "Ring buffer drop ratio.",
	})
)

func main() {
	var (
		interval   = flag.Duration("interval", 5*time.Second, "report interval")
		pidFilter  = flag.Uint("p", 0, "trace only PID")
		commFilter = flag.String("c", "", "trace only COMM (process name)")
		topN       = flag.Int("t", 5, "top-N slowest syscalls in report")
		jsonOut    = flag.String("o", "", "write JSON snapshot to file")
		promAddr   = flag.String("prom-addr", ":2112", "prometheus listen address, empty to disable")
		uprobeBin  = flag.String("uprobe-bin", "", "optional binary path for uprobe attach")
		uprobeSym  = flag.String("uprobe-sym", "main.main", "symbol name for uprobe attach")
	)
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove memlock: %v", err)
	}

	prometheus.MustRegister(metricEventsPerSec, metricLatencyP99MS, metricErrorRate)
	if strings.TrimSpace(*promAddr) != "" {
		go servePrometheus(*promAddr)
	}

	var objs kebpf.KernelpulseObjects
	if err := kebpf.LoadKernelpulseObjects(&objs, nil); err != nil {
		log.Fatalf("load eBPF objects failed: %v\nverifier hint: %s", err, verifierHint(err))
	}
	defer objs.Close()

	if err := configureFilters(objs.Filters, uint32(*pidFilter), *commFilter); err != nil {
		log.Fatalf("configure filter map: %v", err)
	}

	links := make([]link.Link, 0, 10)
	attachTP := func(category, name string, prog *ebpf.Program) {
		l, err := link.Tracepoint(category, name, prog, nil)
		if err != nil {
			log.Fatalf("attach tracepoint %s/%s: %v", category, name, err)
		}
		links = append(links, l)
	}
	attachKP := func(symbol string, prog *ebpf.Program) {
		l, err := link.Kprobe(symbol, prog, nil)
		if err != nil {
			log.Printf("kprobe %s skipped: %v", symbol, err)
			return
		}
		links = append(links, l)
	}

	attachTP("raw_syscalls", "sys_enter", objs.TraceSysEnter)
	attachTP("raw_syscalls", "sys_exit", objs.TraceSysExit)
	attachTP("tcp", "tcp_retransmit_skb", objs.TraceTcpRetransmit)
	attachKP("tcp_rcv_established", objs.TraceTcpRtt)
	attachTP("exceptions", "page_fault_user", objs.TracePageFaultUser)
	attachTP("exceptions", "page_fault_kernel", objs.TracePageFaultKernel)
	attachTP("sched", "sched_wakeup", objs.TraceSchedWakeup)
	attachTP("sched", "sched_switch", objs.TraceSchedSwitch)
	attachTP("sched", "sched_process_exec", objs.TraceSchedExec)
	if strings.TrimSpace(*uprobeBin) != "" {
		if err := attachUprobe(*uprobeBin, *uprobeSym, objs.TraceUserProbe, &links); err != nil {
			log.Printf("uprobe attach skipped: %v", err)
		}
	}
	defer closeLinks(links)

	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("open ringbuf reader: %v", err)
	}
	defer reader.Close()

	var outFile *os.File
	if strings.TrimSpace(*jsonOut) != "" {
		outFile, err = os.OpenFile(*jsonOut, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			log.Fatalf("open output file: %v", err)
		}
		defer outFile.Close()
	}

	agg := collector.NewAggregator()
	readErr := make(chan error, 1)
	go consumeEvents(ctx, reader, agg, readErr)

	counters := newCounterTracker()
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	log.Printf("kernelpulse started interval=%s pid=%d comm=%q topN=%d", interval.String(), *pidFilter, *commFilter, *topN)

	for {
		select {
		case <-ctx.Done():
			log.Printf("stopping")
			return
		case err := <-readErr:
			if err != nil && !errors.Is(err, ringbuf.ErrClosed) {
				log.Fatalf("ringbuf read: %v", err)
			}
			return
		case <-ticker.C:
			if err := counters.collect(objs.Counters); err == nil {
				agg.ObserveRingbufDrops(counters.delta(3))
			}
			snapshot := agg.SnapshotAndReset(*topN)
			updateMetrics(snapshot)
			printSnapshot(snapshot, counters)
			if outFile != nil {
				_ = json.NewEncoder(outFile).Encode(snapshot)
			}
		}
	}
}

func configureFilters(m *ebpf.Map, pid uint32, comm string) error {
	cfg := filterConfig{PID: pid}
	comm = strings.TrimSpace(comm)
	if comm != "" {
		cfg.CommSet = 1
		copy(cfg.Comm[:], comm)
	}
	key := uint32(0)
	return m.Update(&key, &cfg, ebpf.UpdateAny)
}

func consumeEvents(ctx context.Context, reader *ringbuf.Reader, agg *collector.Aggregator, errs chan<- error) {
	defer close(errs)
	for {
		record, err := reader.Read()
		if err != nil {
			errs <- err
			return
		}
		if err := agg.Observe(record.RawSample); err != nil {
			errs <- err
			return
		}
		select {
		case <-ctx.Done():
			_ = reader.Close()
			return
		default:
		}
	}
}

func printSnapshot(s collector.Snapshot, counters *counterTracker) {
	fmt.Printf("\n[%s - %s]\n", s.WindowStart.Format(time.RFC3339), s.WindowEnd.Format(time.RFC3339))
	fmt.Printf("events/sec=%.2f error_rate=%.4f ringbuf_drops=%d\n", s.EventsPerSec, s.ErrorRate, s.RingbufDrops)
	fmt.Printf("syscalls=%d tcp_retrans=%d page_faults=%d sched=%d exec=%d\n", s.Syscalls, s.TCPRetransmits, s.PageFaults, s.SchedEvents, s.ExecEvents)
	fmt.Printf("p99 syscall=%.3fms tcp_rtt=%.3fms runq=%.3fms\n", s.SyscallLatency.P99, s.TCPRTT.P99, s.RunQLatency.P99)
	fmt.Printf("counters: enter=%d exit=%d retrans=%d drop=%d pf=%d wake=%d switch=%d exec=%d tcp_rtt=%d\n",
		counters.delta(0), counters.delta(1), counters.delta(2), counters.delta(3), counters.delta(4),
		counters.delta(5), counters.delta(6), counters.delta(7), counters.delta(8))
	fmt.Println("syscall heatmap:")
	fmt.Print(collector.ASCIIHeatmap(s.SyscallHeatmap))
	fmt.Println("top slow syscalls:")
	for _, row := range s.TopSyscalls {
		fmt.Printf("  %-8s count=%d max=%.3fms avg=%.3fms\n", row.Syscall, row.Count, row.MaxLatencyMS, row.AvgLatencyMS)
	}
	if len(s.TopProcesses) > 0 {
		fmt.Println("top slow processes:")
		for _, row := range s.TopProcesses {
			fmt.Printf("  pid=%d comm=%s count=%d max=%.3fms avg=%.3fms\n", row.PID, row.Comm, row.Count, row.MaxLatencyMS, row.AvgLatencyMS)
		}
	}
}

func updateMetrics(s collector.Snapshot) {
	metricEventsPerSec.Set(s.EventsPerSec)
	metricLatencyP99MS.Set(s.SyscallLatency.P99)
	metricErrorRate.Set(s.ErrorRate)
}

func servePrometheus(addr string) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("prometheus exporter listening on %s", addr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("prometheus exporter stopped: %v", err)
	}
}

func attachUprobe(path, symbol string, prog *ebpf.Program, links *[]link.Link) error {
	ex, err := link.OpenExecutable(path)
	if err != nil {
		return err
	}
	l, err := ex.Uprobe(symbol, prog, nil)
	if err != nil {
		return err
	}
	*links = append(*links, l)
	return nil
}

func closeLinks(links []link.Link) {
	for _, l := range links {
		_ = l.Close()
	}
}

func verifierHint(err error) string {
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "invalid bpf_context access"):
		return "incorrect tracepoint/kprobe context access; check struct fields or use bpf_core_read"
	case strings.Contains(msg, "stack"):
		return "stack access rejected; reduce local stack usage and avoid large structs"
	case strings.Contains(msg, "loop"):
		return "loop rejected; keep bounded loops only"
	case strings.Contains(msg, "permission denied"):
		return "missing capabilities; run as root with CAP_BPF/CAP_PERFMON or privileged container"
	default:
		return "run with bpftool prog load --debug to inspect full verifier log"
	}
}

type counterTracker struct {
	prev map[uint32]uint64
	curr map[uint32]uint64
}

func newCounterTracker() *counterTracker {
	return &counterTracker{
		prev: map[uint32]uint64{},
		curr: map[uint32]uint64{},
	}
}

func (c *counterTracker) collect(m *ebpf.Map) error {
	c.prev = c.curr
	c.curr = make(map[uint32]uint64, 16)
	possibleCPUs, err := ebpf.PossibleCPU()
	if err != nil {
		return err
	}
	for key := uint32(0); key < 16; key++ {
		values := make([]uint64, possibleCPUs)
		if err := m.Lookup(&key, &values); err != nil {
			continue
		}
		var total uint64
		for _, v := range values {
			total += v
		}
		c.curr[key] = total
	}
	return nil
}

func (c *counterTracker) delta(key uint32) uint64 {
	return c.curr[key] - c.prev[key]
}
