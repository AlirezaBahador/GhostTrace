package process

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// Snapshot is a best-effort userspace observation, not an atomic snapshot of
// the kernel event. StartTimeTicks is /proc/<pid>/stat field 22 (clock ticks
// since boot), not an event timestamp or CLOCK_MONOTONIC nanoseconds.
type Snapshot struct {
	PID, PPID      uint32
	Comm           string
	StartTimeTicks uint64
}

// ParseStat handles process names containing spaces and closing parentheses.
func ParseStat(raw []byte) (Snapshot, error) {
	s := strings.TrimSpace(string(raw))
	opening := strings.Index(s, "(")
	closing := strings.LastIndex(s, ")")
	if opening <= 0 || closing <= opening || len(s) <= closing+2 || s[closing+1] != ' ' {
		return Snapshot{}, fmt.Errorf("malformed proc stat header")
	}
	pid64, err := strconv.ParseUint(strings.TrimSpace(s[:opening]), 10, 32)
	if err != nil || pid64 == 0 {
		return Snapshot{}, fmt.Errorf("invalid pid in proc stat")
	}
	// After comm, fields start with field 3 (state). PPID is field 4,
	// and starttime is field 22: indexes 1 and 19 respectively.
	fields := strings.Fields(s[closing+2:])
	if len(fields) < 20 {
		return Snapshot{}, fmt.Errorf("short proc stat")
	}
	ppid64, err := strconv.ParseUint(fields[1], 10, 32)
	if err != nil {
		return Snapshot{}, fmt.Errorf("invalid proc ppid: %w", err)
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || start == 0 {
		return Snapshot{}, fmt.Errorf("invalid proc starttime")
	}
	return Snapshot{PID: uint32(pid64), PPID: uint32(ppid64), Comm: s[opening+1 : closing], StartTimeTicks: start}, nil
}

func ReadSnapshot(pid uint32) (Snapshot, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return Snapshot{}, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil {
		return Snapshot{}, err
	}
	if len(data) > 4096 {
		return Snapshot{}, fmt.Errorf("proc stat exceeds 4096 bytes")
	}
	s, err := ParseStat(data)
	if err != nil {
		return Snapshot{}, err
	}
	if s.PID != pid {
		return Snapshot{}, fmt.Errorf("proc stat PID mismatch")
	}
	return s, nil
}

func ReadExecutable(pid uint32) (string, error) {
	return os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
}
