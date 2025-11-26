//go:build !linux

package cpu

import (
	"errors"
	"testing"
)

func TestStubCollectorBehavior(t *testing.T) {
	if _, err := NewCollector(); !errors.Is(err, errUnsupported) {
		t.Fatalf("expected errUnsupported, got %v", err)
	}

	var c Collector
	if stats, err := c.Snapshot(5); err != errUnsupported || stats != nil {
		t.Fatalf("snapshot should fail with errUnsupported, got stats=%v err=%v", stats, err)
	}

	if rows, err := c.Contention(5); err != errUnsupported || rows != nil {
		t.Fatalf("contention should fail with errUnsupported, got rows=%v err=%v", rows, err)
	}

	if err := c.Reset(); err != nil {
		t.Fatalf("reset should be a no-op, got %v", err)
	}

	if err := c.Close(); err != nil {
		t.Fatalf("close should be a no-op, got %v", err)
	}
}
