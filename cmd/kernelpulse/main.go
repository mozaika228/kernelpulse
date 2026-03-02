//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/mozaika228/kernelpulse/internal/collector"
	kebpf "github.com/mozaika228/kernelpulse/internal/ebpf"
)

func main() {
	interval := flag.Duration("interval", 5*time.Second, "report interval")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove memlock: %v", err)
	}

	var objs kebpf.KernelpulseObjects
	if err := kebpf.LoadKernelpulseObjects(&objs, nil); err != nil {
		log.Fatalf("load eBPF objects: %v", err)
	}
	defer objs.Close()

	links := make([]link.Link, 0, 3)
	attach := func(category, name string, prog *ebpf.Program) {
		l, err := link.Tracepoint(category, name, prog, nil)
		if err != nil {
			log.Fatalf("attach tracepoint %s/%s: %v", category, name, err)
		}
		links = append(links, l)
	}

	attach("raw_syscalls", "sys_enter", objs.TraceSysEnter)
	attach("raw_syscalls", "sys_exit", objs.TraceSysExit)
	attach("tcp", "tcp_retransmit_skb", objs.TraceTcpRetransmit)
	defer func() {
		for _, l := range links {
			_ = l.Close()
		}
	}()

	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("open ringbuf reader: %v", err)
	}
	defer reader.Close()

	agg := collector.NewAggregator()
	readErr := make(chan error, 1)
	go consumeEvents(ctx, reader, agg, readErr)

	counters := newCounterTracker()
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	log.Printf("kernelpulse started, report every %s", interval.String())

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
			if err := counters.collect(objs.Counters); err != nil {
				log.Printf("counter collect failed: %v", err)
			} else {
				agg.ObserveRingbufDrops(counters.delta(3))
			}
			printSnapshot(os.Stdout, agg.SnapshotAndReset(), counters)
		}
	}
}

func consumeEvents(ctx context.Context, reader *ringbuf.Reader, agg *collector.Aggregator, errs chan<- error) {
	defer close(errs)
	for {
		record, err := reader.Read()
		if err != nil {
			errs <- err
			return
		}
		if len(record.RawSample) < 1 {
			continue
		}

		switch collector.EventKind(record.RawSample[0]) {
		case collector.EventSyscall:
			if err := agg.ObserveSyscall(record.RawSample); err != nil {
				errs <- err
				return
			}
		case collector.EventTCPRetransmit:
			if err := agg.ObserveTCPRetransmit(record.RawSample); err != nil {
				errs <- err
				return
			}
		}

		select {
		case <-ctx.Done():
			_ = reader.Close()
			return
		default:
		}
	}
}

func printSnapshot(out *os.File, s collector.Snapshot, counters *counterTracker) {
	fmt.Fprintf(out, "\n[%s - %s]\n", s.WindowStart.Format(time.RFC3339), s.WindowEnd.Format(time.RFC3339))
	fmt.Fprintf(out, "syscalls=%d tcp_retransmits=%d ringbuf_drops=%d\n", s.SyscallCount, s.TCPRetransmits, s.RingbufDrops)
	fmt.Fprintf(out, "counters: enter=%d exit=%d retrans=%d reserve_fail=%d\n", counters.delta(0), counters.delta(1), counters.delta(2), counters.delta(3))
	fmt.Fprintln(out, "latency heatmap (syscalls):")

	keys := make([]string, 0, len(s.SyscallLatencyNS))
	for k := range s.SyscallLatencyNS {
		keys = append(keys, k)
	}
	sort.SliceStable(keys, func(i, j int) bool { return bucketRank(keys[i]) < bucketRank(keys[j]) })
	for _, k := range keys {
		v := s.SyscallLatencyNS[k]
		fmt.Fprintf(out, "  %-8s %6d %s\n", k, v, bar(v))
	}
}

func bar(v uint64) string {
	n := int(v)
	if n > 48 {
		n = 48
	}
	if n == 0 {
		return ""
	}
	return strings.Repeat("#", n)
}

func bucketRank(b string) int {
	order := []string{"<1us", "1-5us", "5-10us", "10-50us", "50-100us", "100-500us", "0.5-1ms", "1-5ms", "5-10ms", ">=10ms"}
	for i, v := range order {
		if b == v {
			return i
		}
	}
	return len(order)
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
	c.curr = make(map[uint32]uint64, 4)

	possibleCPUs, err := ebpf.PossibleCPU()
	if err != nil {
		return err
	}

	for key := uint32(0); key < 4; key++ {
		values := make([]uint64, possibleCPUs)
		if err := m.Lookup(&key, &values); err != nil {
			return err
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
