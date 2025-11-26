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
}

func parseConfig() runConfig {
	interval := flag.Duration("interval", defaultInterval, "sampling interval (e.g. 3s, 1m)")
	topK := flag.Int("topk", types.DefaultTopK, "number of processes to display per section")
	hideKernel := flag.Bool("hide-kernel", true, "hide kernel threads such as kworker, ksoftirqd, etc")
	cgroupFilter := flag.String("cgroup-filter", "", "only show processes whose cgroup path contains this substring (case-insensitive)")
	flag.Parse()

	cfg := runConfig{
		interval:     *interval,
		topK:         *topK,
		hideKernel:   *hideKernel,
		cgroupFilter: strings.ToLower(strings.TrimSpace(*cgroupFilter)),
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

	ticker := time.NewTicker(cfg.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := snapshotAndPrint(cpuCollector, memCollector, cfg); err != nil {
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

func snapshotAndPrint(cpuCollector *cpu.Collector, memCollector *memory.Collector, cfg runConfig) error {
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

	procRows, procIndex := report.BuildProcMetrics(stats, pageFaults, contentionStats, cfg.interval)
	filterCfg := report.FilterConfig{HideKernel: &cfg.hideKernel, CgroupFilter: cfg.cgroupFilter}
	filteredRows := report.FilterMetrics(procRows, filterCfg)
	focus := report.SelectFocusCandidate(filteredRows)

	var buf bytes.Buffer
	buf.WriteString(ui.Banner())
	buf.WriteString("\n")
	fmt.Fprintf(&buf, "hotspot-bpf (press Ctrl+C to exit)\n")
	fmt.Fprintf(&buf, "Updated: %s | Interval: %v\n\n", time.Now().Format(time.RFC3339), cfg.interval)

	if focus != nil {
		fmt.Fprintf(&buf, "[!] Focus: %s (pid %d)\n", focus.Comm, focus.PID)
		fmt.Fprintf(&buf, "   Reason: %s - %s\n\n", focus.Diagnosis, report.FocusSummary(*focus))
	} else if len(filteredRows) == 0 {
		fmt.Fprintf(&buf, "[!] No processes matched current filters (topk=%d, hide-kernel=%t)\n\n", cfg.topK, cfg.hideKernel)
	}

	fmt.Fprintf(&buf, "[Top %d CPU, window %v]\n", cfg.topK, cfg.interval)
	cpuRows := report.CPUUsageRows(filteredRows, cfg.topK)
	if len(cpuRows) == 0 {
		fmt.Fprintln(&buf, "No CPU samples for this window")
	} else {
		tw := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "PID\tCOMM\tCGROUP\tCPU(ms)\tCPU(%%)\tDiag")
		for _, row := range cpuRows {
			fmt.Fprintf(tw, "%d\t%s\t%s\t%.2f\t%.2f\t%s\n", row.PID, row.Comm, row.Cgroup, row.CPUMs, row.CPUPercent, row.Diagnosis)
		}
		tw.Flush()
	}

	if contentionErr != nil {
		fmt.Fprintf(&buf, "\n[CPU Contention unavailable: %v]\n", contentionErr)
	} else {
		fmt.Fprintf(&buf, "\n[CPU Contention - last %v]\n", cfg.interval)
		rows := report.FilterContentionRows(contentionStats, filterCfg, procIndex, cfg.topK)
		if len(rows) == 0 {
			fmt.Fprintln(&buf, "No preemptions recorded in this window")
		} else {
			tw := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "PID\tCOMM\tPREEMPTED BY\tTIMES")
			for _, pair := range rows {
				fmt.Fprintf(tw, "%d\t%s\t%d (%s)\t%d\n", pair.VictimPID, pair.VictimComm, pair.AggressorPID, pair.AggressorComm, pair.Count)
			}
			tw.Flush()
		}
	}

	fmt.Fprintf(&buf, "\n[CPU Cost per Fault - CPU vs Page Faults]\n")
	if pfErr != nil {
		fmt.Fprintf(&buf, "Page fault tracker unavailable: %v\n", pfErr)
	} else {
		costLimit := max(cfg.topK*2, cfg.topK)
		costRows := report.CPUCostRows(filteredRows, costLimit)
		if len(costRows) == 0 {
			fmt.Fprintln(&buf, "No page faults recorded in this window")
		} else {
			tw := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "PID\tCOMM\tCGROUP\tCPU(ms)\tRSS(MB)\tFaults\tFaults/sec\tCPU Cost per Fault (ms)\tDiagnosis")
			for _, row := range costRows {
				fmt.Fprintf(tw, "%d\t%s\t%s\t%.2f\t%.1f\t%d\t%.1f\t%.2f\t%s\n",
					row.PID, row.Comm, row.Cgroup, row.CPUMs, row.RSSMB, row.Faults, row.FaultsPerSec, row.CPUCostPerFault, row.Diagnosis)
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
