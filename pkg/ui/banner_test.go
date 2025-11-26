package ui

import (
	"fmt"
	"strings"
	"testing"
)

// TestBannerPreview prints the banner so `go test ./pkg/ui -run TestBannerPreview` shows it.
func TestBannerPreview(t *testing.T) {
	fmt.Println(Banner())
}

func TestBannerIncludesWordmark(t *testing.T) {
	banner := Banner()
	if !strings.Contains(banner, "hotspot") {
		t.Fatalf("banner missing hotspot wordmark: %q", banner)
	}
	if !strings.Contains(banner, "eBPF performance lens") {
		t.Fatalf("banner missing tagline")
	}
	lines := strings.Split(strings.TrimSpace(banner), "\n")
	if len(lines) < 8 {
		t.Fatalf("expected multi-line banner, got %d lines", len(lines))
	}
}

func TestBannerUsesGradientColors(t *testing.T) {
	banner := Banner()
	colors := []string{bold, hotspotFlame, honeyOrange, beeYellow, mint, cobalt, deepIndigo, fuchsia}
	for _, color := range colors {
		if !strings.Contains(banner, color) {
			t.Fatalf("banner missing color code %q", color)
		}
	}
}
