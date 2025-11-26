package memory

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
		{"noNull", []byte{'x', 'y'}, "xy"},
		{"trimNull", []byte{'x', 0, 'z'}, "x"},
	}
	for _, tc := range cases {
		if got := cStr(tc.input); got != tc.expected {
			t.Fatalf("%s: expected %q, got %q", tc.name, tc.expected, got)
		}
	}
}

func TestCommForPIDHandlesErrorsAndWhitespace(t *testing.T) {
	t.Cleanup(func() { procReadFile = os.ReadFile })
	reads := make(map[uint32]int)

	procReadFile = func(path string) ([]byte, error) {
		if strings.Contains(path, "/42/") {
			reads[42]++
			return []byte("db\n"), nil
		}
		if strings.Contains(path, "/77/") {
			reads[77]++
			return []byte("   \n"), nil
		}
		return nil, errors.New("missing")
	}

	cache := map[uint32]string{}
	if name := commForPID(42, cache); name != "db" {
		t.Fatalf("expected trimmed db, got %q", name)
	}
	if reads[42] != 1 {
		t.Fatalf("expected single read for pid 42, got %d", reads[42])
	}

	if name := commForPID(42, cache); name != "db" || reads[42] != 1 {
		t.Fatalf("expected cached db, got %q with %d reads", name, reads[42])
	}

	if name := commForPID(77, cache); name != "pid-77" {
		t.Fatalf("blank comm should fallback, got %q", name)
	}
	if cache[77] != "pid-77" {
		t.Fatalf("expected fallback cached, got %q", cache[77])
	}

	if name := commForPID(88, cache); name != "pid-88" {
		t.Fatalf("missing file should fallback, got %q", name)
	}
}
