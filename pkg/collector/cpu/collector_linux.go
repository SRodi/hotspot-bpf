//go:build linux
// +build linux

package cpu

import (
	"errors"
	"fmt"
	"runtime"
	"sort"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/srodi/hotspot-bpf/pkg/types"
)

// Collector owns the eBPF programs and maps that record CPU hotspots.
// The BPF program uses tp_btf/sched_switch (BTF-powered raw tracepoint) to get
// direct access to both prev and next task_struct pointers, enabling TGID-based
// keying that matches the memory collector's process-level granularity.
type Collector struct {
	objs hotspot_bpfObjects
	tp   link.Link
}

const resetSweepRetries = 3

// NewCollector loads the compiled eBPF program and attaches it via tp_btf/sched_switch.
// This requires a kernel with BTF support (≥5.5, CONFIG_DEBUG_INFO_BTF=y).
func NewCollector() (*Collector, error) {
	var objs hotspot_bpfObjects
	if err := loadHotspot_bpfObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("loading bpf objects: %w", err)
	}

	tp, err := link.AttachTracing(link.TracingOptions{
		Program: objs.HandleSchedSwitch,
	})
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attaching tp_btf/sched_switch: %w", err)
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

// Snapshot returns per-process (TGID) CPU stats gathered since the previous reset.
// The BPF program aggregates CPU time across all threads of the same process,
// so each entry represents total process CPU time, not individual thread time.
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
			PID:     pid,
			Comm:    cStr(stat.Comm[:]),
			Cgroup:  cStr(stat.Cgroup[:]),
			Ns:      stat.CPUTimeNS,
			CPUCore: stat.CPUId,
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

// Reset clears the BPF maps so the next window can accumulate fresh values.
// It first zeroes the per-CPU state array to invalidate stale TGIDs that would
// otherwise resurrect ghost entries for processes that have already exited.
// The cpu_state reset is best-effort; a failure does not prevent the main
// pid_stats and cpu_contention maps from being cleared.
func (c *Collector) Reset() error {
	// Best-effort: zero cpu_state to prevent ghost entries from dead PIDs.
	// Not fatal because the main map clearing below is more important.
	_ = c.resetCPUState()

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

// resetCPUState zeroes every per-CPU slot of the cpu_state PERCPU_ARRAY.
// This invalidates stale TGIDs so that the BPF handler's
// "if (st->tgid != 0)" guard skips them, preventing ghost pid_stats entries
// for processes that have already exited.
func (c *Collector) resetCPUState() error {
	numCPUs := runtime.NumCPU()
	zeroes := make([]hotspot_bpfCpuState, numCPUs)
	key := uint32(0)
	return c.objs.CpuState.Put(&key, zeroes)
}

// Contention returns the busiest victim/aggressor pairs observed since the last reset.
// Pairs are keyed by TGID (process-level), so intra-process thread switches are
// already filtered out at the BPF level.
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

// pidStat mirrors the BPF struct pid_stat in cpu_hotspot.c.
// Field order and sizes MUST match exactly for correct map iteration.
// Keyed by TGID (process ID), so multi-threaded processes have one entry.
type pidStat struct {
	CPUTimeNS uint64
	Comm      [16]byte
	Cgroup    [64]byte
	CPUId     uint32
	Pad       uint32
}
