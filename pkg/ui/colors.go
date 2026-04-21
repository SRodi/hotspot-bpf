// Package ui color helpers for diagnosis-aware TUI rendering.
// Colors are automatically disabled when stdout is not a TTY or when
// the NO_COLOR environment variable is set (see https://no-color.org).
package ui

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

// ANSI escape sequences for TUI coloring.
const (
	Reset   = "\033[0m"
	Bold    = "\033[1m"
	Dim     = "\033[2m"

	Red     = "\033[38;5;196m"
	Orange  = "\033[38;5;208m"
	Yellow  = "\033[38;5;220m"
	Cyan    = "\033[38;5;81m"
	Blue    = "\033[38;5;33m"
	Gray    = "\033[38;5;245m"
	White   = "\033[38;5;255m"
)

// colorEnabled controls whether ANSI codes are emitted.
// Defaults to true and is set to false when stdout is not a TTY or NO_COLOR is set.
var colorEnabled = true

func init() {
	if os.Getenv("NO_COLOR") != "" {
		colorEnabled = false
		return
	}
	if os.Getenv("TERM") == "dumb" {
		colorEnabled = false
		return
	}
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		colorEnabled = false
	}
}

// SetColorEnabled overrides auto-detection (useful for tests).
func SetColorEnabled(v bool) {
	colorEnabled = v
}

// ColorEnabled returns the current color mode.
func ColorEnabled() bool {
	return colorEnabled
}

// C wraps text with an ANSI color prefix and reset suffix.
// Returns plain text when color is disabled.
func C(color, text string) string {
	if !colorEnabled {
		return text
	}
	return color + text + Reset
}

// DiagColor returns the ANSI color code for a diagnosis label.
func DiagColor(label string) string {
	if !colorEnabled {
		return ""
	}
	switch label {
	case "OOM risk – memory growth":
		return Bold + Red
	case "Mem-thrashing":
		return Bold + Orange
	case "Starved":
		return Yellow
	case "Noisy neighbor":
		return Cyan
	case "CPU-bound":
		return Blue
	default:
		return Dim
	}
}

// DiagLabel returns a diagnosis string wrapped in its severity color.
func DiagLabel(label string) string {
	return C(DiagColor(label), label)
}

// SectionHeader formats a section title with a box-drawing underline.
func SectionHeader(title string) string {
	line := ""
	for i := 0; i < len(title)+2; i++ {
		line += "─"
	}
	if !colorEnabled {
		return fmt.Sprintf("\n%s\n%s\n", title, line)
	}
	return fmt.Sprintf("\n%s%s%s\n%s%s%s\n", Bold, White, title, Dim, line, Reset)
}

func FocusGroupHeader(diagnosis string, count int) string {
	diagColor := DiagColor(diagnosis)
	if !colorEnabled {
		return fmt.Sprintf("\n  [%s] (%d)\n", diagnosis, count)
	}
	return fmt.Sprintf("\n  %s %s\n",
		C(diagColor, diagnosis),
		C(Dim, fmt.Sprintf("(%d)", count)))
}

// FocusEntry formats a single process line within a focus group.
func FocusEntry(comm string, pid uint32, summary string, diagnosis string) string {
	diagColor := DiagColor(diagnosis)
	if !colorEnabled {
		return fmt.Sprintf("    %-16s pid %-8d %s\n", comm, pid, summary)
	}
	indicator := C(diagColor, "▌")
	return fmt.Sprintf("  %s %-16s %s  %s\n",
		indicator,
		C(Bold+White, comm),
		C(Dim, fmt.Sprintf("pid %-8d", pid)),
		C(Gray, summary))
}
