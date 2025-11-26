//go:build linux
// +build linux

package cpu

import (
	"errors"
	"fmt"
	"sort"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/srodi/hotspot-bpf/pkg/types"
)

// Collector owns the eBPF programs and maps that record CPU hotspots.
type Collector struct {
	objs hotspot_bpfObjects
	tp   link.Link
}

const resetSweepRetries = 3

// NewCollector loads the compiled eBPF program and attaches it to sched/sched_switch.
func NewCollector() (*Collector, error) {
	var objs hotspot_bpfObjects
	if err := loadHotspot_bpfObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("loading bpf objects: %w", err)
	}

	tp, err := link.Tracepoint("sched", "sched_switch", objs.HandleSchedSwitch, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attaching tracepoint: %w", err)
	}

	return &Collector{objs: objs, tp: tp}, nil
}

// Close releases the BPF resources and detaches the tracepoint.
func (c *Collector) Close() error {
	var err error
	if c.tp != nil {
		err = errors.Join(err, c.tp.Close())
	}
	return errors.Join(err, c.objs.Close())
}

// Snapshot returns the top N CPU hogs gathered since the previous reset.
func (c *Collector) Snapshot(limit int) ([]types.CPUStat, error) {
	stats := make([]types.CPUStat, 0, limit)

	iter := c.objs.PidStats.Iterate()
	var pid uint32
	var stat pidStat
	for iter.Next(&pid, &stat) {
		if stat.CPUTimeNS == 0 {
			continue
		}

		stats = append(stats, types.CPUStat{
			PID:    pid,
			Comm:   cStr(stat.Comm[:]),
			Cgroup: cStr(stat.Cgroup[:]),
			Ns:     stat.CPUTimeNS,
		})
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterating cpu stats: %w", err)
	}

	sort.Slice(stats, func(i, j int) bool { return stats[i].Ns > stats[j].Ns })
	if limit > 0 && len(stats) > limit {
		stats = stats[:limit]
	}

	return stats, nil
}

// Reset clears the BPF map so the next window can accumulate fresh values.
func (c *Collector) Reset() error {
	for attempt := 1; attempt <= resetSweepRetries; attempt++ {
		iter := c.objs.PidStats.Iterate()
		var pid uint32
		var stat pidStat
		for iter.Next(&pid, &stat) {
			if err := c.objs.PidStats.Delete(&pid); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				return fmt.Errorf("clearing pid %d: %w", pid, err)
			}
		}
		if err := iter.Err(); err != nil {
			if errors.Is(err, ebpf.ErrIterationAborted) && attempt < resetSweepRetries {
				continue
			}
			return err
		}
		break
	}

	if c.objs.CpuContention != nil {
		for attempt := 1; attempt <= resetSweepRetries; attempt++ {
			cIter := c.objs.CpuContention.Iterate()
			var key uint64
			var count uint64
			for cIter.Next(&key, &count) {
				if err := c.objs.CpuContention.Delete(&key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
					return fmt.Errorf("clearing contention entry: %w", err)
				}
			}
			if err := cIter.Err(); err != nil {
				if errors.Is(err, ebpf.ErrIterationAborted) && attempt < resetSweepRetries {
					continue
				}
				return err
			}
			break
		}
	}

	return nil
}

// Contention returns the busiest victim/aggressor pairs observed since the last reset.
func (c *Collector) Contention(limit int) ([]types.ContentionStat, error) {
	if c.objs.CpuContention == nil {
		return nil, fmt.Errorf("contention map is unavailable; regenerate eBPF objects")
	}

	iter := c.objs.CpuContention.Iterate()
	var key uint64
	var count uint64
	cache := make(map[uint32]string)
	stats := make([]types.ContentionStat, 0, limit)
	for iter.Next(&key, &count) {
		if count == 0 {
			continue
		}
		victim := uint32(key >> 32)
		aggressor := uint32(key & 0xffffffff)
		stats = append(stats, types.ContentionStat{
			VictimPID:     victim,
			VictimComm:    commForPID(victim, cache),
			AggressorPID:  aggressor,
			AggressorComm: commForPID(aggressor, cache),
			Count:         count,
		})
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterating cpu contention: %w", err)
	}

	sort.Slice(stats, func(i, j int) bool {
		return stats[i].Count > stats[j].Count
	})
	if limit > 0 && len(stats) > limit {
		stats = stats[:limit]
	}

	return stats, nil
}

type pidStat struct {
	CPUTimeNS uint64
	Comm      [16]byte
	Cgroup    [64]byte
}
