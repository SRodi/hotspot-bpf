package ui

import (
	"strings"
	"testing"
)

func TestDiagColorMapping(t *testing.T) {
	SetColorEnabled(true)
	defer SetColorEnabled(true)

	cases := []struct {
		label     string
		wantEmpty bool
	}{
		{"OOM risk – memory growth", false},
		{"Mem-thrashing", false},
		{"Starved", false},
		{"Noisy neighbor", false},
		{"CPU-bound", false},
		{"OK", false}, // dim, still a color
	}
	for _, tc := range cases {
		color := DiagColor(tc.label)
		if tc.wantEmpty && color != "" {
			t.Errorf("DiagColor(%q) = %q, want empty", tc.label, color)
		}
		if !tc.wantEmpty && color == "" {
			t.Errorf("DiagColor(%q) = empty, want color code", tc.label)
		}
	}
}

func TestDiagColorDisabled(t *testing.T) {
	SetColorEnabled(false)
	defer SetColorEnabled(true)

	for _, label := range []string{"OOM risk – memory growth", "Starved", "OK"} {
		if color := DiagColor(label); color != "" {
			t.Errorf("DiagColor(%q) with color disabled = %q, want empty", label, color)
		}
	}
}

func TestDiagLabel(t *testing.T) {
	SetColorEnabled(true)
	defer SetColorEnabled(true)

	label := DiagLabel("OOM risk – memory growth")
	if !strings.Contains(label, "OOM risk") {
		t.Errorf("DiagLabel missing text: %q", label)
	}
	if !strings.Contains(label, Reset) {
		t.Errorf("DiagLabel missing reset code: %q", label)
	}
}

func TestDiagLabelNoColor(t *testing.T) {
	SetColorEnabled(false)
	defer SetColorEnabled(true)

	label := DiagLabel("Starved")
	if label != "Starved" {
		t.Errorf("DiagLabel with color disabled = %q, want plain text", label)
	}
}

func TestCColored(t *testing.T) {
	SetColorEnabled(true)
	defer SetColorEnabled(true)

	result := C(Red, "error")
	if !strings.Contains(result, "error") {
		t.Errorf("C() missing text")
	}
	if !strings.HasSuffix(result, Reset) {
		t.Errorf("C() missing reset suffix")
	}
}

func TestCNoColor(t *testing.T) {
	SetColorEnabled(false)
	defer SetColorEnabled(true)

	result := C(Red, "error")
	if result != "error" {
		t.Errorf("C() with color disabled = %q, want plain text", result)
	}
}

func TestSectionHeader(t *testing.T) {
	SetColorEnabled(false)
	defer SetColorEnabled(true)

	header := SectionHeader("Test Section")
	if !strings.Contains(header, "Test Section") {
		t.Error("SectionHeader missing title")
	}
	if !strings.Contains(header, "─") {
		t.Error("SectionHeader missing underline")
	}
}
