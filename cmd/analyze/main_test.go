package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/AlirezaBahador/GhostTrace/internal/detection"
	"github.com/AlirezaBahador/GhostTrace/pkg/events"
)

func testEngine(t *testing.T) *detection.Engine {
	t.Helper()
	rule := []byte("id: GT-901\nname: Test Shell\nenabled: true\nseverity: high\nconditions:\n  parent_process:\n    - nginx\n  child_process:\n    - sh\nactions:\n  - alert\n")
	r, err := detection.ParseRule(rule)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := detection.New([]detection.Rule{r})
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func TestAnalyzeJSONL(t *testing.T) {
	e := events.Event{SchemaVersion: events.SchemaVersion, EventID: "trigger-1", EventType: events.ProcessExec,
		Timestamp: time.Now().UTC(), TimestampSource: "userspace_receive", Source: "ebpf",
		Host:    events.Host{Hostname: "host", BootID: "boot"},
		Process: events.Process{PID: 55, TID: 55, Comm: "sh", Parent: &events.Parent{PID: 10, Comm: "nginx"}}}
	in, _ := json.Marshal(e)
	var out bytes.Buffer
	count, err := Analyze(context.Background(), bytes.NewReader(append(in, '\n')), &out, testEngine(t))
	if err != nil || count != 1 {
		t.Fatalf("count %d err %v", count, err)
	}
	var alert events.Event
	if err := json.Unmarshal(out.Bytes(), &alert); err != nil {
		t.Fatal(err)
	}
	if alert.EventType != events.DetectionAlert || alert.Detection.TriggeringEventIDs[0] != "trigger-1" {
		t.Fatalf("bad alert %+v", alert)
	}
	e.Process.Parent = nil
	in, _ = json.Marshal(e)
	count, err = Analyze(context.Background(), bytes.NewReader(append(in, '\n')), &bytes.Buffer{}, testEngine(t))
	if err != nil || count != 0 {
		t.Fatalf("unknown parent matched: %d %v", count, err)
	}
}

func TestAnalyzeRejectsCorruptInput(t *testing.T) {
	for _, src := range []string{"not json\n", "{}\n", "{}{}\n", strings.Repeat("x", MaxJSONLine+2) + "\n"} {
		if _, err := Analyze(context.Background(), strings.NewReader(src), &bytes.Buffer{}, testEngine(t)); err == nil {
			t.Fatal("accepted invalid input")
		}
	}
}
