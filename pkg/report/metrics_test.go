package report

import (
	"math"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/srodi/hotspot-bpf/pkg/collector/memory"
	"github.com/srodi/hotspot-bpf/pkg/types"
)

func TestBuildProcMetricsMergesStats(t *testing.T) {
	t.Cleanup(func() { rssBytesForPIDs = memory.RSSBytesForPIDs })
	rssBytesForPIDs = func(pids []int) map[int]uint64 {
		return map[int]uint64{
			123: 200 << 20,
			456: 64 << 20,
		}
	}

	interval := time.Second
	cpuNs := uint64((50 * time.Millisecond).Nanoseconds())
	cpuStats := []types.CPUStat{{PID: 123, Comm: "worker", Cgroup: "/kubepods", Ns: cpuNs}}
	pageFaults := []types.PageFaultStat{{PID: 123, Comm: "worker", Cgroup: "/kubepods", Faults: 25, FaultsPerSec: 25}}
	contention := []types.ContentionStat{{VictimPID: 123, VictimComm: "worker", AggressorPID: 456, AggressorComm: "noisy", Count: 150}}

	rows, index := BuildProcMetrics(cpuStats, pageFaults, contention, interval)
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(rows))
	}
	victim, ok := index[123]
	if !ok {
		t.Fatalf("missing victim row")
	}
	if victim.CPUNs != cpuNs {
		t.Fatalf("unexpected CPUNs: %d", victim.CPUNs)
	}
	if math.Abs(victim.CPUMs-float64(cpuNs)/1e6) > 1e-6 {
		t.Fatalf("unexpected CPUMs: %.3f", victim.CPUMs)
	}
	expectedPercent := 100 * float64(cpuNs) / (float64(interval.Nanoseconds()) * float64(runtime.NumCPU()))
	if math.Abs(victim.CPUPercent-expectedPercent) > 1e-6 {
		t.Fatalf("unexpected CPU%%: got %.4f want %.4f", victim.CPUPercent, expectedPercent)
	}
	if math.Abs(victim.RSSMB-200) > 1e-3 {
		t.Fatalf("unexpected RSSMB: %.3f", victim.RSSMB)
	}
	if victim.Faults != 25 || victim.FaultsPerSec != 25 {
		t.Fatalf("unexpected fault stats: %+v", victim)
	}
	expectedCost := (victim.CPUMs / interval.Seconds()) / (victim.FaultsPerSec + 1)
	if math.Abs(victim.CPUCostPerFault-expectedCost) > 1e-6 {
		t.Fatalf("unexpected CPU cost per fault: %.6f", victim.CPUCostPerFault)
	}
	if victim.Preempted != 150 || victim.PreemptsOthers != 0 {
		t.Fatalf("preemption counters wrong: %+v", victim)
	}
	if victim.Diagnosis != "Starved" {
		t.Fatalf("unexpected diagnosis: %s", victim.Diagnosis)
	}

	aggressor, ok := index[456]
	if !ok {
		t.Fatalf("missing aggressor row")
	}
	if aggressor.PreemptsOthers != 150 {
		t.Fatalf("expected aggressor to preempt 150x, got %d", aggressor.PreemptsOthers)
	}
	if aggressor.Preempted != 0 {
		t.Fatalf("aggressor should not be preempted: %+v", aggressor)
	}
	if aggressor.RSSMB != 64 {
		t.Fatalf("unexpected aggressor RSSMB: %.3f", aggressor.RSSMB)
	}
}

func TestBuildProcMetricsDefaultsInterval(t *testing.T) {
	t.Cleanup(func() { rssBytesForPIDs = memory.RSSBytesForPIDs })
	rssBytesForPIDs = func(pids []int) map[int]uint64 { return nil }

	cpuNs := uint64((2 * time.Millisecond).Nanoseconds())
	cpuStats := []types.CPUStat{{PID: 99, Comm: "tiny", Cgroup: "/scope", Ns: cpuNs}}
	pageFaults := []types.PageFaultStat{{PID: 99, Comm: "tiny", Cgroup: "/scope", Faults: 10}}

	_, index := BuildProcMetrics(cpuStats, pageFaults, nil, 0)
	row := index[99]
	if row.CPUMs != float64(cpuNs)/1e6 {
		t.Fatalf("unexpected CPUMs: %.3f", row.CPUMs)
	}
	if row.FaultsPerSec != 0 {
		t.Fatalf("expected FaultsPerSec to stay zero, got %.3f", row.FaultsPerSec)
	}
	expectedCost := (float64(cpuNs) / 1e6) / (float64(row.Faults) + 1)
	if math.Abs(row.CPUCostPerFault-expectedCost) > 1e-6 {
		t.Fatalf("unexpected CPU cost with zero interval fallback: %.6f", row.CPUCostPerFault)
	}
}

func TestFilterMetricsRespectsKernelAndCgroup(t *testing.T) {
	rows := []ProcMetrics{
		{PID: 1, Comm: "kworker/0:1", Cgroup: "/kernel"},
		{PID: 42, Comm: "api", Cgroup: "/kubepods/burst"},
		{PID: 43, Comm: "db", Cgroup: "/docker/db"},
	}

	visible := FilterMetrics(rows, FilterConfig{})
	if len(visible) != 2 {
		t.Fatalf("expected 2 user rows, got %d", len(visible))
	}
	cfg := FilterConfig{HideKernel: boolPtr(false), CgroupFilter: "kube"}
	scoped := FilterMetrics(rows, cfg)
	if len(scoped) != 1 || scoped[0].PID != 42 {
		t.Fatalf("expected only kube cgroup row, got %+v", scoped)
	}
}

func TestCPUUsageRows(t *testing.T) {
	rows := []ProcMetrics{
		{PID: 1, CPUNs: 0},
		{PID: 2, CPUNs: 10},
		{PID: 3, CPUNs: 5},
	}
	top := CPUUsageRows(rows, 2)
	if len(top) != 2 {
		t.Fatalf("expected top 2 rows, got %d", len(top))
	}
	if top[0].PID != 2 || top[1].PID != 3 {
		t.Fatalf("unexpected order: %+v", top)
	}
}

func TestCPUCostRowsSortingAndLimit(t *testing.T) {
	rows := []ProcMetrics{
		{PID: 1, Faults: 10, CPUMs: 10, CPUCostPerFault: 5, FaultsPerSec: 1},
		{PID: 2, Faults: 20, CPUMs: 20, CPUCostPerFault: 3, FaultsPerSec: 4},
		{PID: 3, Faults: 15, CPUMs: 25, CPUCostPerFault: 3, FaultsPerSec: 2},
		{PID: 4, Faults: 0, CPUMs: 0, CPUCostPerFault: 0},
	}
	top := CPUCostRows(rows, 2)
	if len(top) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(top))
	}
	if top[0].PID != 2 || top[1].PID != 3 {
		t.Fatalf("unexpected ordering: %+v", top)
	}
}

func TestFilterContentionRows(t *testing.T) {
	procIndex := map[uint32]ProcMetrics{
		101: {PID: 101, Comm: "svc", Cgroup: "/kubepods/stateful"},
		202: {PID: 202, Comm: "db", Cgroup: "/kubepods/burst"},
		303: {PID: 303, Comm: "kworker/0:1", Cgroup: "/kernel"},
	}
	entries := []types.ContentionStat{
		{VictimPID: 101, AggressorPID: 202, Count: 5},
		{VictimPID: 101, AggressorPID: 303, Count: 1},
		{VictimPID: 999, AggressorPID: 202, Count: 1},
	}

	filtered := FilterContentionRows(entries, FilterConfig{}, procIndex, 0)
	if len(filtered) != 1 || filtered[0].AggressorPID != 202 {
		t.Fatalf("expected only user processes, got %+v", filtered)
	}

	cfg := FilterConfig{HideKernel: boolPtr(false), CgroupFilter: "state"}
	limited := FilterContentionRows(entries, cfg, procIndex, 1)
	if len(limited) != 1 || limited[0].VictimPID != 101 {
		t.Fatalf("expected stateful rows after topK, got %+v", limited)
	}
}

func TestSelectFocusCandidate(t *testing.T) {
	t.Run("severityPreferred", func(t *testing.T) {
		rows := []ProcMetrics{
			{PID: 1, Diagnosis: "OK", CPUPercent: 60, FaultsPerSec: 10},
			{PID: 2, Diagnosis: "Starved", CPUPercent: 5, FaultsPerSec: 2},
			{PID: 3, Diagnosis: "Mem-thrashing", CPUPercent: 1, FaultsPerSec: 2},
		}
		candidate := SelectFocusCandidate(rows)
		if candidate == nil || candidate.PID != 3 {
			t.Fatalf("expected Mem-thrashing row, got %+v", candidate)
		}
	})

	t.Run("fallbackToMaxCPU", func(t *testing.T) {
		rows := []ProcMetrics{
			{PID: 10, Diagnosis: "OK", CPUPercent: 0.5, FaultsPerSec: 0.2},
			{PID: 11, Diagnosis: "OK", CPUPercent: 5, FaultsPerSec: 0.2},
		}
		candidate := SelectFocusCandidate(rows)
		if candidate == nil || candidate.PID != 11 {
			t.Fatalf("expected highest CPU row, got %+v", candidate)
		}
	})
}

func TestFocusSummary(t *testing.T) {
	cases := []struct {
		name     string
		row      ProcMetrics
		expected string
	}{
		{"thrash", ProcMetrics{Diagnosis: "Mem-thrashing", FaultsPerSec: 1200, CPUPercent: 4, Preempted: 3}, "faults/sec"},
		{"starved", ProcMetrics{Diagnosis: "Starved", Preempted: 200, CPUPercent: 2}, "preempted"},
		{"neighbor", ProcMetrics{Diagnosis: "Noisy neighbor", PreemptsOthers: 50, CPUPercent: 40}, "steals"},
		{"cpu", ProcMetrics{Diagnosis: "CPU-bound", CPUPercent: 70, FaultsPerSec: 12}, "CPU"},
		{"default", ProcMetrics{Diagnosis: "OK", CPUPercent: 3, FaultsPerSec: 1}, "faults/sec"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			summary := FocusSummary(tc.row)
			if !strings.Contains(summary, tc.expected) {
				t.Fatalf("summary %q does not contain %q", summary, tc.expected)
			}
		})
	}
}

func TestClassifyProc(t *testing.T) {
	cases := []struct {
		name     string
		row      ProcMetrics
		expected string
	}{
		{"cpuBound", ProcMetrics{CPUPercent: 60, FaultsPerSec: 0.5}, "CPU-bound"},
		{"thrashByCost", ProcMetrics{CPUPercent: 10, FaultsPerSec: 800, CPUCostPerFault: 0.2, Faults: 200}, "Mem-thrashing"},
		{"thrashByVeryCostly", ProcMetrics{CPUPercent: 5, FaultsPerSec: 1500, CPUCostPerFault: 0.8, Faults: 20}, "Mem-thrashing"},
		{"starved", ProcMetrics{CPUPercent: 5, Preempted: 200}, "Starved"},
		{"neighbor", ProcMetrics{CPUPercent: 35, PreemptsOthers: 120}, "Noisy neighbor"},
		{"ok", ProcMetrics{CPUPercent: 5}, "OK"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			label := classifyProc(&tc.row)
			if label != tc.expected {
				t.Fatalf("expected %s, got %s", tc.expected, label)
			}
		})
	}
}

func TestClassifyProcTableDrivenScenarios(t *testing.T) {
	testCases := []struct {
		name string
		row  ProcMetrics
		want string
	}{
		{
			name: "cpuBound",
			row:  ProcMetrics{CPUPercent: 75, FaultsPerSec: 0.5, Preempted: 0},
			want: "CPU-bound",
		},
		{
			name: "oomRisk",
			row:  ProcMetrics{RSSMB: 2048, FaultsPerSec: 500, RSSRatio: 0.4},
			want: "OOM risk – memory growth",
		},
		{
			name: "memThrashing",
			row:  ProcMetrics{CPUPercent: 10, FaultsPerSec: 800, CPUCostPerFault: 0.2, Faults: 300},
			want: "Mem-thrashing",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			label := classifyProc(&tc.row)
			if label != tc.want {
				t.Fatalf("expected %s, got %s", tc.want, label)
			}
		})
	}
}

func TestDiagnosisSeverity(t *testing.T) {
	labels := map[string]int{
		"Mem-thrashing":  4,
		"Starved":        3,
		"Noisy neighbor": 2,
		"CPU-bound":      1,
		"OK":             0,
	}
	for label, expected := range labels {
		if got := diagnosisSeverity(label); got != expected {
			t.Fatalf("severity mismatch for %s: got %d want %d", label, got, expected)
		}
	}
}

func TestIsKernelThread(t *testing.T) {
	cases := []struct {
		row      ProcMetrics
		expected bool
	}{
		{ProcMetrics{PID: 0}, true},
		{ProcMetrics{PID: 1, Comm: "kworker/0:1"}, true},
		{ProcMetrics{PID: 2, Comm: "ksoftirqd/1"}, true},
		{ProcMetrics{PID: 3, Comm: "user"}, false},
	}
	for _, tc := range cases {
		if got := isKernelThread(tc.row); got != tc.expected {
			t.Fatalf("kernel detection mismatch for %+v: got %v", tc.row, got)
		}
	}
}

func TestPassesFilters(t *testing.T) {
	row := ProcMetrics{PID: 10, Comm: "app", Cgroup: "/kubepods"}
	if !passesFilters(row, FilterConfig{}) {
		t.Fatalf("expected row to pass default filters")
	}
	if passesFilters(ProcMetrics{PID: 1, Comm: "kworker"}, FilterConfig{}) {
		t.Fatalf("kernel thread should be hidden by default")
	}
	cfg := FilterConfig{HideKernel: boolPtr(false), CgroupFilter: "kube"}
	if !passesFilters(row, cfg) {
		t.Fatalf("expected kube row to pass cgroup filter")
	}
	cfg.CgroupFilter = "db"
	if passesFilters(row, cfg) {
		t.Fatalf("unexpected cgroup match")
	}
}

func boolPtr(v bool) *bool { return &v }
