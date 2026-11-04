package events

import (
	"encoding/json"
	"regexp"
	"testing"
	"time"

	"github.com/AlirezaBahador/GhostTrace/internal/decoder"
)

func TestFromRecordAndJSONSchema(t *testing.T) {
	received := time.Date(2026, 11, 4, 12, 30, 0, 3*1e8, time.FixedZone("offset", 3600))
	host := Host{Hostname: "sample-host", BootID: "boot-123"}
	r := decoder.ProcessRecord{MonotonicNS: 9876, PID: 42, TID: 42, UID: 0, GID: 10, Kind: decoder.KindExec, Comm: "bash"}
	e, err := FromRecord(r, host, received)
	if err != nil {
		t.Fatal(err)
	}
	if e.EventType != ProcessExec || e.TimestampSource != "userspace_receive" || e.KernelMonotonicNS != 9876 {
		t.Fatalf("bad event: %+v", e)
	}
	if !e.Timestamp.Equal(received) || e.Timestamp.Location() != time.UTC {
		t.Errorf("not UTC: %v", e.Timestamp)
	}
	match := regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`)
	if !match.MatchString(e.EventID) {
		t.Errorf("invalid event UUID v4: %s", e.EventID)
	}
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"schema_version", "event_id", "event_type", "timestamp", "timestamp_source", "kernel_monotonic_ns", "host", "process", "source"} {
		if _, ok := m[key]; !ok {
			t.Errorf("missing JSON key %s", key)
		}
	}
	if _, hasPPID := m["ppid"]; hasPPID {
		t.Fatal("not yet collected ppid was fabricated")
	}
}

func TestFromRecordExitAndInvalid(t *testing.T) {
	host := Host{Hostname: "host", BootID: "boot"}
	r := decoder.ProcessRecord{PID: 1, TID: 1, Kind: decoder.KindExit}
	e, err := FromRecord(r, host, time.Now())
	if err != nil || e.EventType != ProcessExit {
		t.Fatalf("exit event: %v %+v", err, e)
	}
	r.Kind = 500
	if _, err := FromRecord(r, host, time.Now()); err == nil {
		t.Fatal("expected unsupported kind error")
	}
	r.Kind = decoder.KindExec
	if _, err := FromRecord(r, Host{}, time.Now()); err == nil {
		t.Fatal("expected host validation error")
	}
}
