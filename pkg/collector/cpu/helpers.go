package cpu

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// procReadFile allows tests to stub reading /proc/PID/comm.
var procReadFile = os.ReadFile

func cStr(b []byte) string {
	n := bytes.IndexByte(b, 0)
	if n == -1 {
		return string(b)
	}
	return string(b[:n])
}

func commForPID(pid uint32, cache map[uint32]string) string {
	if pid == 0 {
		return "idle"
	}
	if name, ok := cache[pid]; ok {
		return name
	}
	path := filepath.Join("/proc", strconv.FormatUint(uint64(pid), 10), "comm")
	data, err := procReadFile(path)
	if err != nil {
		name := fmt.Sprintf("pid-%d", pid)
		cache[pid] = name
		return name
	}
	comm := strings.TrimSpace(string(data))
	if comm == "" {
		comm = fmt.Sprintf("pid-%d", pid)
	}
	cache[pid] = comm
	return comm
}
