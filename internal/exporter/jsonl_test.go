package exporter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/ghosttrace/ghosttrace/pkg/events"
)

func sampleEvent() events.Event {
	return events.Event{
		SchemaVersion: events.SchemaVersion, EventID: "uuid", EventType: events.ProcessExec,
		Timestamp: time.Now().UTC(), TimestampSource: "userspace_receive",
		Host:    events.Host{Hostname: "localhost", BootID: "test-boot"},
		Process: events.Process{PID: 1, TID: 1, Comm: "init"}, Source: "ebpf",
	}
}
func TestOneJSONLinePerEvent(t *testing.T) {
	var buffer bytes.Buffer
	writer := NewJSONL(&buffer)
	for i := 0; i < 2; i++ {
		if err := writer.Write(context.Background(), sampleEvent()); err != nil {
			t.Fatal(err)
		}
	}
	lines := strings.Split(strings.TrimSpace(buffer.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected two lines, got %q", buffer.String())
	}
	for _, line := range lines {
		var decoded events.Event
		if err := json.Unmarshal([]byte(line), &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.EventType != events.ProcessExec {
			t.Fatalf("wrong event: %+v", decoded)
		}
	}
}

type brokenWriter struct{}

func (brokenWriter) Write(_ []byte) (int, error) { return 0, io.ErrClosedPipe }
func TestPropagateWriteError(t *testing.T) {
	if err := NewJSONL(brokenWriter{}).Write(context.Background(), sampleEvent()); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("error not preserved: %v", err)
	}
	bad := sampleEvent()
	bad.Process.PID = 0
	if err := NewJSONL(io.Discard).Write(context.Background(), bad); err == nil {
		t.Fatal("invalid event accepted")
	}
}
