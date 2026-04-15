// hotspot-bpf main package — the CLI entry point.
//
// Initializes eBPF collectors for CPU and memory, then runs a ticker loop
// that follows this lifecycle each tick:
//
//   1. Snapshot: read BPF maps (cpu_stats, contention, page_faults)
//   2. Merge:    combine all stats into per-PID ProcMetrics rows
//   3. Classify: assign a diagnosis to each process (OK, Starved, OOM risk, etc.)
//   4. Render:   write the TUI tables to an alternate terminal buffer
//   5. Reset:    clear all BPF maps for the next sampling window
//
// The reset-after-render pattern means all metrics are windowed — they reflect
// only the activity since the previous tick, not cumulative totals.

//go:build linux

package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/srodi/hotspot-bpf/pkg/collector/cpu"
	"github.com/srodi/hotspot-bpf/pkg/collector/memory"
	"github.com/srodi/hotspot-bpf/pkg/config"
	"github.com/srodi/hotspot-bpf/pkg/report"
	"github.com/srodi/hotspot-bpf/pkg/types"
	"github.com/srodi/hotspot-bpf/pkg/ui"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

const defaultInterval = 5 * time.Second

type runConfig struct {
	interval     time.Duration
	topK         int
	hideKernel   bool
	cgroupFilter string
	thresholds   config.Thresholds
}

func parseConfig() runConfig {
	interval := flag.Duration("interval", defaultInterval, "sampling interval (e.g. 3s, 1m)")
	topK := flag.Int("topk", types.DefaultTopK, "number of processes to display per section")
	hideKernel := flag.Bool("hide-kernel", true, "hide kernel threads such as kworker, ksoftirqd, etc")
	cgroupFilter := flag.String("cgroup-filter", "", "only show processes whose cgroup path contains this substring (case-insensitive)")
	configPath := flag.String("config", "", "path to YAML config file for classification thresholds (see -generate-config)")
	generateConfig := flag.Bool("generate-config", false, "print the default config YAML to stdout and exit")
	flag.Parse()

	if *generateConfig {
		fmt.Print(config.DefaultYAML())
		os.Exit(0)
	}

	th := config.Default()
	if *configPath != "" {
		var err error
		th, err = config.LoadFile(*configPath)
		if err != nil {
			log.Fatalf("loading config: %v", err)
		}
	}

	cfg := runConfig{
		interval:     *interval,
		topK:         *topK,
		hideKernel:   *hideKernel,
		cgroupFilter: strings.ToLower(strings.TrimSpace(*cgroupFilter)),
		thresholds:   th,
	}
	if cfg.interval <= 0 {
		cfg.interval = defaultInterval
	}
	if cfg.topK <= 0 {
		cfg.topK = 1
	}
	return cfg
}

func main() {
	// Raise rlimit for locked memory to allow eBPF programs to load.
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}); err != nil {
		log.Fatalf("failed to raise rlimit memlock: %v", err)
	}

	cfg := parseConfig()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cpuCollector, err := cpu.NewCollector()
	if err != nil {
		log.Fatalf("initializing CPU collector: %v", err)
	}
	defer cpuCollector.Close()

	memCollector, err := memory.NewCollector()
	if err != nil {
		log.Fatalf("initializing memory collector: %v", err)
	}
	defer memCollector.Close()

	cleanupTerminal := enableSingleView()
	defer cleanupTerminal()

	rssTracker := report.NewRSSTracker(cfg.thresholds.RSSTracker.WindowTicks)

	ticker := time.NewTicker(cfg.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := snapshotAndPrint(cpuCollector, memCollector, cfg, rssTracker); err != nil {
				log.Printf("snapshot failed: %v", err)
			}
			if err := cpuCollector.Reset(); err != nil {
				log.Printf("reset failed: %v", err)
			}
			if err := memCollector.Reset(); err != nil {
				log.Printf("memory reset failed: %v", err)
			}
		}
	}
}

func snapshotAndPrint(cpuCollector *cpu.Collector, memCollector *memory.Collector, cfg runConfig, rssTracker *report.RSSTracker) error {
	cpuLimit := max(cfg.topK*3, cfg.topK)
	stats, err := cpuCollector.Snapshot(cpuLimit)
	if err != nil {
		return err
	}
	contentionLimit := max(cfg.topK*4, cfg.topK)
	contentionStats, contentionErr := cpuCollector.Contention(contentionLimit)
	if contentionErr != nil {
		contentionStats = nil
	}

	pageFaultLimit := max(cfg.topK*3, cfg.topK*2)
	pageFaults, pfErr := memCollector.Snapshot(pageFaultLimit, cfg.interval)
	if pfErr != nil {
		pageFaults = nil
	}

	procRows, procIndex := report.BuildProcMetrics(stats, pageFaults, contentionStats, cfg.interval, rssTracker, cfg.thresholds)
	filterCfg := report.FilterConfig{HideKernel: &cfg.hideKernel, CgroupFilter: cfg.cgroupFilter}
	filteredRows := report.FilterMetrics(procRows, filterCfg)
	focusGroups := report.SelectFocusGroups(filteredRows)

	var buf bytes.Buffer
	buf.WriteString(ui.Banner())

	timestamp := ui.C(ui.Dim, time.Now().Format(time.RFC3339))
	interval := ui.C(ui.Dim, cfg.interval.String())
	fmt.Fprintf(&buf, "%s  %s │ %s  %s\n",
		ui.C(ui.Bold+ui.White, "hotspot-bpf"), ui.C(ui.Dim, "(Ctrl+C to exit)"),
		ui.C(ui.Gray, "Updated:"), timestamp)
	fmt.Fprintf(&buf, "%s  %s\n", ui.C(ui.Gray, "Interval:"), interval)

	// Focus section — all non-OK processes grouped by diagnosis
	if len(focusGroups) > 0 {
		buf.WriteString(ui.SectionHeader("Focus · Processes requiring attention"))
		for _, group := range focusGroups {
			buf.WriteString(ui.FocusGroupHeader(group.Diagnosis, len(group.Procs)))
			for _, proc := range group.Procs {
				buf.WriteString(ui.FocusEntry(proc.Comm, proc.PID, report.FocusSummary(proc), proc.Diagnosis))
			}
		}
	} else if len(filteredRows) == 0 {
		fmt.Fprintf(&buf, "\n%s No processes matched current filters (topk=%d, hide-kernel=%t)\n",
			ui.C(ui.Dim, "[–]"), cfg.topK, cfg.hideKernel)
	}

	// CPU Usage table
	buf.WriteString(ui.SectionHeader(fmt.Sprintf("CPU Hotspots · Top %d processes by CPU time (window %v)", cfg.topK, cfg.interval)))
	cpuRows := report.CPUUsageRows(filteredRows, cfg.topK)
	if len(cpuRows) == 0 {
		fmt.Fprintln(&buf, ui.C(ui.Dim, "No CPU samples for this window"))
	} else {
		tw := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "PID\tCOMM\tCGROUP\tCPU(ms)\tCPU(%)\tCore%\tLastCore\tDiag")
		for _, row := range cpuRows {
			diag := ui.DiagLabel(row.Diagnosis)
			fmt.Fprintf(tw, "%d\t%s\t%s\t%.2f\t%.2f\t%.1f\t%d\t%s\n",
				row.PID, row.Comm, row.Cgroup, row.CPUMs, row.CPUPercent,
				row.CoreCPUPercent, row.CPUCore, diag)
		}
		tw.Flush()
	}

	// CPU Contention table
	if contentionErr != nil {
		buf.WriteString(ui.SectionHeader("Scheduler Contention"))
		fmt.Fprintf(&buf, "%s\n", ui.C(ui.Dim, fmt.Sprintf("unavailable: %v", contentionErr)))
	} else {
		buf.WriteString(ui.SectionHeader(fmt.Sprintf("Scheduler Contention · Which processes preempt others (window %v)", cfg.interval)))
		rows := report.FilterContentionRows(contentionStats, filterCfg, procIndex, cfg.topK)
		if len(rows) == 0 {
			fmt.Fprintln(&buf, ui.C(ui.Dim, "No preemptions recorded in this window"))
		} else {
			tw := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "VICTIM PID\tVICTIM\tAGGRESSOR PID\tAGGRESSOR\tCOUNT")
			for _, pair := range rows {
				fmt.Fprintf(tw, "%d\t%s\t%d\t%s\t%d\n",
					pair.VictimPID, pair.VictimComm, pair.AggressorPID, pair.AggressorComm, pair.Count)
			}
			tw.Flush()
		}
	}

	// Memory Pressure table
	buf.WriteString(ui.SectionHeader(fmt.Sprintf("Memory Pressure · Top %d processes by page fault rate", cfg.topK)))
	if pfErr != nil {
		fmt.Fprintf(&buf, "%s\n", ui.C(ui.Dim, fmt.Sprintf("Page fault tracker unavailable: %v", pfErr)))
	} else {
		costRows := report.CPUCostRows(filteredRows, cfg.topK)
		if len(costRows) == 0 {
			fmt.Fprintln(&buf, ui.C(ui.Dim, "No page faults recorded in this window"))
		} else {
			tw := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "PID\tCOMM\tCGROUP\tCPU(ms)\tRSS(MB)\tFaults\tFaults/sec\tCost/Fault(ms)\tDiag")
			for _, row := range costRows {
				diag := ui.DiagLabel(row.Diagnosis)
				fmt.Fprintf(tw, "%d\t%s\t%s\t%.2f\t%.1f\t%d\t%.1f\t%.2f\t%s\n",
					row.PID, row.Comm, row.Cgroup, row.CPUMs, row.RSSMB,
					row.Faults, row.FaultsPerSec, row.CPUCostPerFault, diag)
			}
			tw.Flush()
		}
	}

	clearScreen()
	fmt.Print(buf.String())
	return nil
}

func clearScreen() {
	fmt.Print("\033[H\033[2J")
}

func enableSingleView() func() {
	stdoutFD := int(os.Stdout.Fd())
	stdinFD := int(os.Stdin.Fd())
	if !term.IsTerminal(stdoutFD) {
		return func() {}
	}

	fmt.Print("\033[?1049h") // switch to alternate buffer
	fmt.Print("\033[?25l")   // hide cursor

	var restore []func()
	if term.IsTerminal(stdinFD) {
		if undoEcho, err := disableInputEcho(stdinFD); err != nil {
			log.Printf("unable to suppress stdin echo: %v", err)
		} else if undoEcho != nil {
			restore = append(restore, undoEcho)
		}
	}

	return func() {
		for i := len(restore) - 1; i >= 0; i-- {
			restore[i]()
		}
		fmt.Print("\033[?25h")   // show cursor
		fmt.Print("\033[?1049l") // restore main buffer
	}
}

// disableInputEcho turns off stdin echo so the alternate-screen view stays clean.
func disableInputEcho(fd int) (func(), error) {
	termState, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return nil, err
	}

	updated := *termState
	updated.Lflag &^= unix.ECHO

	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &updated); err != nil {
		return nil, err
	}

	return func() {
		_ = unix.IoctlSetTermios(fd, unix.TCSETS, termState)
	}, nil
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
