package types

// DefaultTopK controls how many top processes we display per resource category.
const DefaultTopK = 5

// CPUStat holds information about how much CPU time a PID consumed during a window.
type CPUStat struct {
	PID    uint32
	Comm   string
	Cgroup string
	Ns     uint64
}

// ContentionStat captures how often one PID preempted another within a window.
type ContentionStat struct {
	VictimPID     uint32
	VictimComm    string
	AggressorPID  uint32
	AggressorComm string
	Count         uint64
}

// MemStat describes the RSS footprint for a process.
type MemStat struct {
	PID      int
	Comm     string
	RSSBytes uint64
}

// PageFaultStat tracks per-PID major+minor faults during a window.
type PageFaultStat struct {
	PID          uint32
	Comm         string
	Cgroup       string
	Faults       uint64
	FaultsPerSec float64
}
