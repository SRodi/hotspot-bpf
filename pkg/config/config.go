// Package config defines the classification thresholds used by the hotspot-bpf
// diagnosis engine. All values can be overridden via a YAML configuration file
// passed with the -config flag. See DefaultYAML for the annotated default.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Thresholds holds every tunable classification parameter.
// Field names match the YAML keys. See DefaultYAML for documentation
// of each field's purpose and guidance on how to adjust it.
type Thresholds struct {
	OOM          OOMThresholds          `yaml:"oom"`
	CPUBound     CPUBoundThresholds     `yaml:"cpu_bound"`
	MemThrashing MemThrashingThresholds `yaml:"mem_thrashing"`
	Starved      StarvedThresholds      `yaml:"starved"`
	NoisyNeighbr NoisyNeighborThresholds `yaml:"noisy_neighbor"`
	RSSTracker   RSSTrackerConfig       `yaml:"rss_tracker"`
}

// OOMThresholds controls when a process is classified as "OOM risk – memory growth".
type OOMThresholds struct {
	RSSMB        float64 `yaml:"rss_mb"`         // minimum absolute RSS in MB
	RSSRatio     float64 `yaml:"rss_ratio"`       // minimum RSS as fraction of total RAM (0.0–1.0)
	FaultsPerSec float64 `yaml:"faults_per_sec"`  // minimum sustained page-fault rate
}

// CPUBoundThresholds controls when a process is classified as "CPU-bound".
type CPUBoundThresholds struct {
	CPUPercent      float64 `yaml:"cpu_percent"`        // minimum system-wide CPU usage percentage
	CoreCPUPercent  float64 `yaml:"core_cpu_percent"`   // minimum single-core CPU usage percentage
	MaxFaultsPerSec float64 `yaml:"max_faults_per_sec"` // faults/sec must be BELOW this
	MaxPreempted    uint64  `yaml:"max_preempted"`      // preemption count must be AT or BELOW this
}

// MemThrashingThresholds controls when a process is classified as "Mem-thrashing".
// Three tiers:
//   - "severe"  — very costly faults (major faults from disk/swap)
//   - "moderate" — costly faults
//   - "volume"  — very high fault rate regardless of per-fault cost (minor-fault storms)
type MemThrashingThresholds struct {
	SevereFaultsPerSec   float64 `yaml:"severe_faults_per_sec"`   // fault rate for severe tier
	SevereCostPerFault   float64 `yaml:"severe_cost_per_fault"`   // CPU cost/fault (ms) for severe tier
	ModerateFaultsPerSec float64 `yaml:"moderate_faults_per_sec"` // fault rate for moderate tier
	ModerateCostPerFault float64 `yaml:"moderate_cost_per_fault"` // CPU cost/fault (ms) for moderate tier
	HighFaultsPerSec     float64 `yaml:"high_faults_per_sec"`     // fault rate for volume tier (cost-independent)
	MaxCPUPercent        float64 `yaml:"max_cpu_percent"`         // CPU must be BELOW this (rules out CPU-bound)
}

// StarvedThresholds controls when a process is classified as "Starved".
type StarvedThresholds struct {
	MinPreempted uint64  `yaml:"min_preempted"`  // minimum preemption count in the window
	MaxCPUPercent float64 `yaml:"max_cpu_percent"` // CPU must be BELOW this
}

// NoisyNeighborThresholds controls when a process is classified as "Noisy neighbor".
type NoisyNeighborThresholds struct {
	MinPreemptsOthers uint64  `yaml:"min_preempts_others"` // minimum times this PID preempted others
	MinCPUPercent     float64 `yaml:"min_cpu_percent"`      // CPU must be ABOVE this
}

// RSSTrackerConfig controls the trend-based RSS growth detector.
type RSSTrackerConfig struct {
	WindowTicks int     `yaml:"window_ticks"` // number of ticks to keep in history
	MinDeltaMB  float64 `yaml:"min_delta_mb"` // minimum net RSS growth (MB) to flag as "growing"
}

// Default returns the built-in default thresholds.
func Default() Thresholds {
	return Thresholds{
		OOM: OOMThresholds{
			RSSMB:        500,
			RSSRatio:     0.10,
			FaultsPerSec: 200,
		},
		CPUBound: CPUBoundThresholds{
			CPUPercent:      50,
			CoreCPUPercent:  90,
			MaxFaultsPerSec: 10,
			MaxPreempted:    50,
		},
		MemThrashing: MemThrashingThresholds{
			SevereFaultsPerSec:   1000,
			SevereCostPerFault:   0.5,
			ModerateFaultsPerSec: 500,
			ModerateCostPerFault: 0.1,
			HighFaultsPerSec:     10000,
			MaxCPUPercent:        20,
		},
		Starved: StarvedThresholds{
			MinPreempted:  100,
			MaxCPUPercent: 10,
		},
		NoisyNeighbr: NoisyNeighborThresholds{
			MinPreemptsOthers: 100,
			MinCPUPercent:     30,
		},
		RSSTracker: RSSTrackerConfig{
			WindowTicks: 3,
			MinDeltaMB:  10,
		},
	}
}

// LoadFile reads a YAML config file and merges it with the defaults.
// Any field not specified in the file retains its default value.
func LoadFile(path string) (Thresholds, error) {
	cfg := Default()
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("reading config file: %w", err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parsing config file: %w", err)
	}
	return cfg, nil
}

// DefaultYAML returns the default configuration as a commented YAML string,
// suitable for writing to a file as a starting point.
func DefaultYAML() string {
	return `# hotspot-bpf classification thresholds
#
# This file controls how processes are diagnosed in the TUI Focus banner.
# All values below are the built-in defaults. Uncomment and adjust as needed.
#
# Diagnosis precedence (highest to lowest):
#   1. OOM risk – memory growth
#   2. CPU-bound
#   3. Mem-thrashing
#   4. Starved
#   5. Noisy neighbor
#   6. OK (default, no rule matched)
#
# A process is evaluated top-to-bottom and receives the first matching label.
# See docs/diagnosis-guide.md for detailed explanations of each diagnosis.

# --- OOM risk – memory growth ---
# Triggers when a process has GROWING RSS (trend-based) AND exceeds size/fault
# thresholds. All three conditions must be met simultaneously.
#
# Lowering rss_mb or rss_ratio makes detection more sensitive but may flag
# normal large applications. Raising faults_per_sec reduces false positives
# but delays detection of slow leaks.
oom:
  rss_mb: 500            # RSS >= this value (MB) OR rss_ratio is met
  rss_ratio: 0.10        # RSS >= this fraction of total RAM (0.0–1.0)
  faults_per_sec: 200    # page faults/sec >= this value

# --- CPU-bound ---
# Triggers when a process uses significant CPU without memory pressure.
# A process matches if EITHER system-wide cpu_percent OR single-core
# core_cpu_percent is exceeded. On multi-core machines, a single-threaded
# busy loop shows low system CPU% but ~100% on one core — core_cpu_percent
# catches this case so a fully saturated core is always flagged.
cpu_bound:
  cpu_percent: 50        # system-wide CPU usage must exceed this (%)
  core_cpu_percent: 90   # single-core CPU usage must exceed this (%)
  max_faults_per_sec: 10 # faults/sec must be below this (minor faults are normal)
  max_preempted: 50      # preemption count must be at or below this

# --- Mem-thrashing ---
# Three tiers: severe (very costly faults), moderate (costly faults), and
# volume (very high fault rate regardless of per-fault cost).
# The cost-based tiers catch major faults from disk/swap. The volume tier
# catches minor-fault storms (e.g., repeated madvise+re-fault cycles) where
# individual faults are cheap but the sustained rate is abnormally high.
# All tiers require CPU to be low — high CPU + high faults is usually
# computation, not thrashing.
mem_thrashing:
  severe_faults_per_sec: 1000   # fault rate for severe tier
  severe_cost_per_fault: 0.5    # CPU ms per fault for severe tier
  moderate_faults_per_sec: 500  # fault rate for moderate tier
  moderate_cost_per_fault: 0.1  # CPU ms per fault for moderate tier
  high_faults_per_sec: 10000   # fault rate for volume tier (cost-independent)
  max_cpu_percent: 20           # CPU must be below this (%)

# --- Starved ---
# Triggers when a process is frequently preempted and gets little CPU.
# In high-contention environments, raise min_preempted to reduce noise.
starved:
  min_preempted: 100     # preempted at least this many times in the window
  max_cpu_percent: 10    # CPU must be below this (%)

# --- Noisy neighbor ---
# Triggers when a process frequently preempts others while using significant CPU.
# Lower min_preempts_others to catch less aggressive neighbors.
noisy_neighbor:
  min_preempts_others: 100  # preempted other processes at least this many times
  min_cpu_percent: 30       # CPU must exceed this (%)

# --- RSS trend tracker ---
# Controls the growth detection that gates OOM classification.
# Increasing window_ticks requires longer sustained growth before triggering.
# Increasing min_delta_mb ignores small fluctuations.
rss_tracker:
  window_ticks: 3    # number of sampling ticks to track (minimum 2)
  min_delta_mb: 10   # net RSS growth (MB) required to flag as "growing"
`
}
