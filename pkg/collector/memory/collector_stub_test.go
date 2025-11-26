//go:build !linux

package memory

import (
	"errors"
	"testing"
	"time"
)

func TestMemoryStubCollectorBehavior(t *testing.T) {
	if _, err := NewCollector(); !errors.Is(err, errUnsupported) {
		t.Fatalf("expected errUnsupported, got %v", err)
	}

	var c Collector
	if stats, err := c.Snapshot(5, time.Second); err != errUnsupported || stats != nil {
		t.Fatalf("snapshot should fail with errUnsupported, got stats=%v err=%v", stats, err)
	}

	if err := c.Reset(); err != nil {
		t.Fatalf("reset should no-op, got %v", err)
	}

	if err := c.Close(); err != nil {
		t.Fatalf("close should no-op, got %v", err)
	}
}
