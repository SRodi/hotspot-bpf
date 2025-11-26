//go:build linux
// +build linux

package memory

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/srodi/hotspot-bpf/pkg/types"
)

// Collector owns the eBPF program tracking per-PID page faults.
type Collector struct {
	objs memory_bpfObjects
	hook link.Link
}

const resetSweepRetries = 3

// NewCollector loads the page fault tracker and attaches it to the always-available
// handle_mm_fault kprobe so we always capture fault activity.
func NewCollector() (*Collector, error) {
	var objs memory_bpfObjects
	if err := loadMemory_bpfObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("loading memory bpf objects: %w", err)
	}

	kp, kerr := link.Kprobe("handle_mm_fault", objs.HandleMmFaultKprobe, nil)
	if kerr != nil {
		objs.Close()
		return nil, fmt.Errorf("attaching handle_mm_fault kprobe failed: %w", kerr)
	}

	return &Collector{objs: objs, hook: kp}, nil
}

// Close releases the BPF resources.
func (c *Collector) Close() error {
	var err error
	if c.hook != nil {
		err = errors.Join(err, c.hook.Close())
	}
	return errors.Join(err, c.objs.Close())
}

// Snapshot returns the busiest PIDs by page faults for the current window.
func (c *Collector) Snapshot(limit int, window time.Duration) ([]types.PageFaultStat, error) {
	stats := make([]types.PageFaultStat, 0, limit)
	iter := c.objs.PageFaults.Iterate()
	var pid uint32
	var stat faultStat

	cache := make(map[uint32]string)
	windowSeconds := window.Seconds()
	if windowSeconds <= 0 {
		windowSeconds = 1
	}

	for iter.Next(&pid, &stat) {
		if stat.Faults == 0 {
			continue
		}
		stats = append(stats, types.PageFaultStat{
			PID:          pid,
			Comm:         commForPID(pid, cache),
			Cgroup:       cStr(stat.Cgroup[:]),
			Faults:       stat.Faults,
			FaultsPerSec: float64(stat.Faults) / windowSeconds,
		})
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterating page fault map: %w", err)
	}

	sort.Slice(stats, func(i, j int) bool { return stats[i].Faults > stats[j].Faults })
	if limit > 0 && len(stats) > limit {
		stats = stats[:limit]
	}

	return stats, nil
}

// Reset clears the page fault map for the next interval.
func (c *Collector) Reset() error {
	for attempt := 1; attempt <= resetSweepRetries; attempt++ {
		iter := c.objs.PageFaults.Iterate()
		var pid uint32
		var stat faultStat
		for iter.Next(&pid, &stat) {
			if err := c.objs.PageFaults.Delete(&pid); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				return fmt.Errorf("clearing pid %d: %w", pid, err)
			}
		}
		if err := iter.Err(); err != nil {
			if errors.Is(err, ebpf.ErrIterationAborted) && attempt < resetSweepRetries {
				continue
			}
			return fmt.Errorf("iterating page fault map: %w", err)
		}
		return nil
	}
	return nil
}

type faultStat struct {
	Faults uint64
	Cgroup [64]byte
}
