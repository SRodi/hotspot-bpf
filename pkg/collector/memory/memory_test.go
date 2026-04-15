package memory

import (
	"os"
	"testing"
)

func TestRSSBytesForSelf(t *testing.T) {
	pid := os.Getpid()
	rssMap := RSSBytesForPIDs([]int{pid})
	rss, ok := rssMap[pid]
	if !ok {
		t.Fatalf("expected RSS entry for own pid %d", pid)
	}
	if rss == 0 {
		t.Fatalf("RSS for own process should be > 0, got 0")
	}
}

func TestRSSBytesForPIDsSkipsExitedProcess(t *testing.T) {
	// PID 999999999 almost certainly doesn't exist.
	rssMap := RSSBytesForPIDs([]int{999999999})
	if _, ok := rssMap[999999999]; ok {
		t.Fatalf("expected no entry for non-existent pid")
	}
}

func TestRSSBytesForPIDsSkipsInvalid(t *testing.T) {
	rssMap := RSSBytesForPIDs([]int{0, -1})
	if len(rssMap) != 0 {
		t.Fatalf("expected empty map for invalid pids, got %v", rssMap)
	}
}

func TestRSSBytesForPIDsDeduplicates(t *testing.T) {
	pid := os.Getpid()
	rssMap := RSSBytesForPIDs([]int{pid, pid, pid})
	if len(rssMap) != 1 {
		t.Fatalf("expected 1 entry after dedup, got %d", len(rssMap))
	}
	if rssMap[pid] == 0 {
		t.Fatalf("RSS should be > 0 for own process")
	}
}

func TestTotalMemoryBytes(t *testing.T) {
	total, err := TotalMemoryBytes()
	if err != nil {
		t.Fatalf("TotalMemoryBytes: %v", err)
	}
	if total < 1<<20 {
		t.Fatalf("total memory %d seems too small", total)
	}
}
