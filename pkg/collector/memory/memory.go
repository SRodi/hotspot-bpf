package memory

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// rssBytes returns the resident set size for a single PID.
func rssBytes(pid int) (uint64, error) {
	if pid <= 0 {
		return 0, fmt.Errorf("invalid pid %d", pid)
	}
	statmPath := filepath.Join("/proc", strconv.Itoa(pid), "statm")
	data, err := os.ReadFile(statmPath)
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		return 0, fmt.Errorf("unexpected statm format for pid %d", pid)
	}
	rssPages, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0, err
	}
	return rssPages * uint64(os.Getpagesize()), nil
}

// RSSBytesForPIDs returns a PID->RSS map for the provided set.
func RSSBytesForPIDs(pids []int) map[int]uint64 {
	result := make(map[int]uint64, len(pids))
	seen := make(map[int]struct{}, len(pids))
	for _, pid := range pids {
		if pid <= 0 {
			continue
		}
		if _, ok := seen[pid]; ok {
			continue
		}
		seen[pid] = struct{}{}
		if rss, err := rssBytes(pid); err == nil {
			result[pid] = rss
		}
	}
	return result
}

// TotalMemoryBytes returns the total system memory in bytes.
// TODO: future scenario, consider container memory limits
func TotalMemoryBytes() (uint64, error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				return 0, fmt.Errorf("unexpected format for MemTotal")
			}
			kb, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil {
				return 0, err
			}
			return kb * 1024, nil // bytes
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return 0, fmt.Errorf("MemTotal not found in /proc/meminfo")
}
