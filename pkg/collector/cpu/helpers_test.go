package cpu

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestCStr(t *testing.T) {
	cases := []struct {
		name     string
		input    []byte
		expected string
	}{
		{"noNull", []byte{'a', 'b'}, "ab"},
		{"withNull", []byte{'a', 'b', 0, 'c'}, "ab"},
	}
	for _, tc := range cases {
		if got := cStr(tc.input); got != tc.expected {
			t.Fatalf("%s: expected %q, got %q", tc.name, tc.expected, got)
		}
	}
}

func TestCommForPIDReadsOnceAndCaches(t *testing.T) {
	t.Cleanup(func() { procReadFile = os.ReadFile })

	calls := 0
	procReadFile = func(path string) ([]byte, error) {
		calls++
		if strings.Contains(path, "/123/") {
			return []byte("worker\n"), nil
		}
		return nil, errors.New("boom")
	}

	cache := map[uint32]string{}
	name := commForPID(123, cache)
	if name != "worker" {
		t.Fatalf("expected worker, got %q", name)
	}
	if calls != 1 {
		t.Fatalf("expected single read, got %d", calls)
	}

	reused := commForPID(123, cache)
	if reused != "worker" || calls != 1 {
		t.Fatalf("expected cached worker, got %q with %d reads", reused, calls)
	}

	fallback := commForPID(456, cache)
	if fallback != "pid-456" {
		t.Fatalf("expected fallback pid-456, got %q", fallback)
	}
	if cached := cache[456]; cached != fallback {
		t.Fatalf("fallback name not cached: %q", cached)
	}

	if idle := commForPID(0, cache); idle != "idle" {
		t.Fatalf("expected idle for pid 0, got %q", idle)
	}
}
