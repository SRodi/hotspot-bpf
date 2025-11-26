package report

import (
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/srodi/hotspot-bpf/pkg/collector/memory"
	"github.com/srodi/hotspot-bpf/pkg/types"
)

// rssBytesForPIDs allows tests to stub RSS lookups that normally hit /proc.
var rssBytesForPIDs = memory.RSSBytesForPIDs

// ProcMetrics condenses CPU, memory, and contention stats for a PID during one sample window.
type ProcMetrics struct {
	PID             uint32
	Comm            string
	Cgroup          string
	CPUNs           uint64
	CPUMs           float64
	CPUPercent      float64
	RSSMB           float64
	RSSRatio        float64
	Faults          uint64
	FaultsPerSec    float64
	CPUCostPerFault float64
	Preempted       uint64
	PreemptsOthers  uint64
	Diagnosis       string
}

// FilterConfig controls which processes appear in CLI tables.
type FilterConfig struct {
	HideKernel   *bool // nil defaults to true so kernel threads stay hidden unless explicitly shown
	CgroupFilter string
}

func (cfg FilterConfig) hideKernelEnabled() bool {
	if cfg.HideKernel == nil {
		return true
	}
	return *cfg.HideKernel
}

// BuildProcMetrics merges raw collector stats into per-PID rows and returns both
// a slice for table rendering and an index for quick lookups.
func BuildProcMetrics(
	cpuStats []types.CPUStat,
	pageFaults []types.PageFaultStat,
	contention []types.ContentionStat,
	interval time.Duration,
) ([]ProcMetrics, map[uint32]ProcMetrics) {
	// compute once
	totalMemBytes, err := memory.TotalMemoryBytes()
	if err != nil || totalMemBytes == 0 {
		totalMemBytes = 1
	}

	rows := make(map[uint32]*ProcMetrics)
	ensure := func(pid uint32) *ProcMetrics {
		if pid == 0 {
			return nil
		}
		if row, ok := rows[pid]; ok {
			return row
		}
		row := &ProcMetrics{PID: pid}
		rows[pid] = row
		return row
	}

	totalCapacity := float64(interval.Nanoseconds()) * float64(runtime.NumCPU())
	intervalSeconds := interval.Seconds()
	if intervalSeconds <= 0 {
		intervalSeconds = 1
	}
	for _, stat := range cpuStats {
		row := ensure(stat.PID)
		if row == nil {
			continue
		}
		row.Comm = stat.Comm
		if row.Cgroup == "" {
			row.Cgroup = stat.Cgroup
		}
		row.CPUNs = stat.Ns
		row.CPUMs = float64(stat.Ns) / 1e6
		if totalCapacity > 0 {
			row.CPUPercent = 100 * float64(stat.Ns) / totalCapacity
		}
	}

	for _, pf := range pageFaults {
		row := ensure(pf.PID)
		if row == nil {
			continue
		}
		if row.Comm == "" {
			row.Comm = pf.Comm
		}
		if row.Cgroup == "" {
			row.Cgroup = pf.Cgroup
		}
		row.Faults = pf.Faults
		row.FaultsPerSec = pf.FaultsPerSec
	}

	for _, pair := range contention {
		if victim := ensure(pair.VictimPID); victim != nil {
			if victim.Comm == "" {
				victim.Comm = pair.VictimComm
			}
			victim.Preempted += pair.Count
		}
		if aggressor := ensure(pair.AggressorPID); aggressor != nil {
			if aggressor.Comm == "" {
				aggressor.Comm = pair.AggressorComm
			}
			aggressor.PreemptsOthers += pair.Count
		}
	}

	pidList := make([]int, 0, len(rows))
	for pid := range rows {
		pidList = append(pidList, int(pid))
	}
	rssMap := rssBytesForPIDs(pidList)
	for pid, rss := range rssMap {
		if row, ok := rows[uint32(pid)]; ok {
			row.RSSMB = float64(rss) / (1024 * 1024)
		}
	}

	result := make([]ProcMetrics, 0, len(rows))
	index := make(map[uint32]ProcMetrics, len(rows))
	for _, row := range rows {
		cpuMsPerSec := row.CPUMs / intervalSeconds
		faultRate := row.FaultsPerSec
		if faultRate == 0 && row.Faults > 0 {
			faultRate = float64(row.Faults) / intervalSeconds
		}
		row.RSSRatio = (row.RSSMB * 1024 * 1024) / float64(totalMemBytes)
		row.CPUCostPerFault = cpuMsPerSec / (faultRate + 1)
		row.Diagnosis = classifyProc(row)
		copy := *row
		result = append(result, copy)
		index[row.PID] = copy
	}

	return result, index
}

// FilterMetrics applies HideKernel/cgroup filters before ranking tables.
func FilterMetrics(rows []ProcMetrics, cfg FilterConfig) []ProcMetrics {
	filtered := make([]ProcMetrics, 0, len(rows))
	for _, row := range rows {
		if passesFilters(row, cfg) {
			filtered = append(filtered, row)
		}
	}
	return filtered
}

// CPUUsageRows returns the highest CPUNs rows up to topK.
func CPUUsageRows(rows []ProcMetrics, topK int) []ProcMetrics {
	candidates := make([]ProcMetrics, 0, len(rows))
	for _, row := range rows {
		if row.CPUNs == 0 {
			continue
		}
		candidates = append(candidates, row)
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].CPUNs > candidates[j].CPUNs })
	if topK > 0 && len(candidates) > topK {
		candidates = candidates[:topK]
	}
	return candidates
}

// CPUCostRows orders processes by CPU cost per fault to spotlight memory pressure.
func CPUCostRows(rows []ProcMetrics, topK int) []ProcMetrics {
	candidates := make([]ProcMetrics, 0, len(rows))
	for _, row := range rows {
		if row.Faults == 0 && row.CPUMs == 0 {
			continue
		}
		candidates = append(candidates, row)
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].CPUCostPerFault == candidates[j].CPUCostPerFault {
			return candidates[i].FaultsPerSec > candidates[j].FaultsPerSec
		}
		return candidates[i].CPUCostPerFault < candidates[j].CPUCostPerFault
	})
	if topK > 0 && len(candidates) > topK {
		candidates = candidates[:topK]
	}
	return candidates
}

// FilterContentionRows removes contention pairs hidden by filters and limits rows.
func FilterContentionRows(entries []types.ContentionStat, cfg FilterConfig, procIndex map[uint32]ProcMetrics, topK int) []types.ContentionStat {
	if len(entries) == 0 {
		return nil
	}
	rows := make([]types.ContentionStat, 0, len(entries))
	hideKernel := cfg.hideKernelEnabled()
	for _, entry := range entries {
		victim, vok := procIndex[entry.VictimPID]
		aggressor, aok := procIndex[entry.AggressorPID]
		if !vok || !aok {
			continue
		}
		if hideKernel && (isKernelThread(victim) || isKernelThread(aggressor)) {
			continue
		}
		if cfg.CgroupFilter != "" {
			vMatch := strings.Contains(strings.ToLower(victim.Cgroup), cfg.CgroupFilter)
			aMatch := strings.Contains(strings.ToLower(aggressor.Cgroup), cfg.CgroupFilter)
			if !vMatch && !aMatch {
				continue
			}
		}
		rows = append(rows, entry)
	}
	if topK > 0 && len(rows) > topK {
		rows = rows[:topK]
	}
	return rows
}

// SelectFocusCandidate picks the most interesting process to summarize for the operator.
func SelectFocusCandidate(rows []ProcMetrics) *ProcMetrics {
	if len(rows) == 0 {
		return nil
	}
	var best *ProcMetrics
	bestScore := -1.0
	for _, row := range rows {
		severity := diagnosisSeverity(row.Diagnosis)
		if severity == 0 && row.CPUPercent < 1 && row.FaultsPerSec < 1 {
			continue
		}
		score := float64(severity)*1000 + row.CPUPercent
		if best == nil || score > bestScore {
			copy := row
			best = &copy
			bestScore = score
		}
	}
	if best != nil {
		return best
	}
	maxIdx := 0
	for i := 1; i < len(rows); i++ {
		if rows[i].CPUPercent > rows[maxIdx].CPUPercent {
			maxIdx = i
		}
	}
	copy := rows[maxIdx]
	return &copy
}

// FocusSummary returns a short explanation string for the status line.
func FocusSummary(row ProcMetrics) string {
	switch row.Diagnosis {
	case "Mem-thrashing":
		return fmt.Sprintf("%.0f faults/sec, %.1f%% CPU, preempted %dx",
			row.FaultsPerSec, row.CPUPercent, row.Preempted)
	case "Starved":
		return fmt.Sprintf("preempted %dx, only %.1f%% CPU",
			row.Preempted, row.CPUPercent)
	case "Noisy neighbor":
		return fmt.Sprintf("steals CPU %dx, running at %.1f%%",
			row.PreemptsOthers, row.CPUPercent)
	case "CPU-bound":
		return fmt.Sprintf("%.1f%% CPU, faults/sec %.0f",
			row.CPUPercent, row.FaultsPerSec)
	case "OOM risk – memory growth":
		return fmt.Sprintf("OOM risk – %.1f GB RSS, %.0f faults/sec",
			row.RSSMB/1024.0, row.FaultsPerSec)
	default:
		return fmt.Sprintf("%.1f%% CPU, %.0f faults/sec",
			row.CPUPercent, row.FaultsPerSec)
	}
}

var totalMemOnce sync.Once
var totalMem uint64

func getTotalMem() uint64 {
	totalMemOnce.Do(func() {
		if v, err := memory.TotalMemoryBytes(); err == nil {
			totalMem = v
		} else {
			totalMem = 1 // safe fallback
		}
	})
	return totalMem
}

func classifyProc(row *ProcMetrics) string {
	costlyFaults := row.CPUCostPerFault > 0.1 && row.Faults > 0
	veryCostlyFaults := row.CPUCostPerFault > 0.5 && row.Faults > 0

	rssRatio := row.RSSRatio
	bigProcess := row.RSSMB > 1000       // > 1GB
	highRatio := rssRatio > 0.3          // > 30% of RAM
	manyFaults := row.FaultsPerSec > 200 // lots of PFs

	// --- highest priority: OOM-ish behavior ---
	if (bigProcess || highRatio) && manyFaults {
		return "OOM risk – memory growth"
	}

	// CPU-bound
	if row.CPUPercent > 50 && row.FaultsPerSec < 1 && row.Preempted == 0 {
		return "CPU-bound"
	}

	// Memory thrashing (expensive faults)
	if row.FaultsPerSec > 1000 && veryCostlyFaults && row.CPUPercent < 20 {
		return "Mem-thrashing"
	}
	if row.FaultsPerSec > 500 && costlyFaults && row.CPUPercent < 20 {
		return "Mem-thrashing"
	}

	// Scheduler-based diagnoses
	if row.Preempted > 100 && row.CPUPercent < 10 {
		return "Starved"
	}
	if row.PreemptsOthers > 100 && row.CPUPercent > 30 {
		return "Noisy neighbor"
	}

	return "OK"
}

func passesFilters(row ProcMetrics, cfg FilterConfig) bool {
	if cfg.hideKernelEnabled() && isKernelThread(row) {
		return false
	}
	if cfg.CgroupFilter != "" {
		cg := strings.ToLower(row.Cgroup)
		if !strings.Contains(cg, cfg.CgroupFilter) {
			return false
		}
	}
	return true
}

func isKernelThread(row ProcMetrics) bool {
	if row.PID == 0 {
		return true
	}
	name := strings.ToLower(row.Comm)
	switch {
	case strings.HasPrefix(name, "kworker"), strings.HasPrefix(name, "ksoftirqd"), strings.HasPrefix(name, "kthreadd"),
		strings.HasPrefix(name, "migration"), strings.HasPrefix(name, "watchdog"), strings.HasPrefix(name, "rcu"),
		strings.HasPrefix(name, "irq/"):
		return true
	}
	return false
}

func diagnosisSeverity(label string) int {
	switch label {
	case "Mem-thrashing":
		return 4
	case "Starved":
		return 3
	case "Noisy neighbor":
		return 2
	case "CPU-bound":
		return 1
	default:
		return 0
	}
}
