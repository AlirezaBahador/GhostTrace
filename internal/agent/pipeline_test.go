package agent

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/ghosttrace/ghosttrace/internal/decoder"
	"github.com/ghosttrace/ghosttrace/pkg/events"
)

type addParent struct{}

func (addParent) Enrich(e *events.Event) { e.Process.Parent = &events.Parent{PID: 1, Comm: "nginx"} }

type matchShell struct{}

func (matchShell) Evaluate(e events.Event) ([]events.Event, error) {
	if e.Process.Parent == nil {
		return nil, errors.New("enrichment did not precede detection")
	}
	if e.Process.Comm != "sh" {
		return nil, nil
	}
	alert, err := events.NewDetectionAlert(e, events.Detection{RuleID: "GT-001", RuleName: "shell", Severity: "high", TriggeringEventIDs: []string{e.EventID}, MatchedConditions: []string{"process.comm=sh"}}, e.Timestamp)
	if err != nil {
		return nil, err
	}
	return []events.Event{alert}, nil
}

func TestEnrichmentDetectionAndFilter(t *testing.T) {
	source := &fakeSource{ch: make(chan decoder.ProcessRecord, 2)}
	sink := &fakeSink{}
	source.ch <- decoder.ProcessRecord{PID: 1, TID: 1, Kind: decoder.KindExec, Comm: "sh"}
	source.ch <- decoder.ProcessRecord{PID: 2, TID: 2, Kind: decoder.KindExec, Comm: "sleep"}
	source.Stop()
	stats, err := RunWithOptions(context.Background(), source, sink, events.Host{Hostname: "h", BootID: "b"}, Options{
		Enricher: addParent{}, Detector: matchShell{}, IncludeComm: map[string]bool{"sleep": true},
	})
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected source end: %v", err)
	}
	if stats.Emitted != 2 || stats.Alerts != 1 || stats.Filtered != 1 || len(sink.events) != 2 {
		t.Fatalf("stats %+v events %+v", stats, sink.events)
	}
	if sink.events[0].EventType != events.DetectionAlert || sink.events[1].Process.Comm != "sleep" {
		t.Fatal("alert not emitted despite process filter")
	}
}

func TestScopedTelemetryFiltersDoNotFilterDetection(t *testing.T) {
	source := &fakeSource{ch: make(chan decoder.ProcessRecord, 2)}
	sink := &fakeSink{}
	source.ch <- decoder.ProcessRecord{PID: 1, TID: 1, UID: 33, Kind: decoder.KindExec, Comm: "sh"}
	source.ch <- decoder.ProcessRecord{PID: 2, TID: 2, UID: 1000, Kind: decoder.KindExit, Comm: "sleep"}
	source.Stop()
	stats, err := RunWithOptions(context.Background(), source, sink, events.Host{Hostname: "h", BootID: "b"}, Options{
		Enricher: addParent{}, Detector: matchShell{}, IncludeUID: map[uint32]bool{1000: true}, IncludeEventType: map[string]bool{events.ProcessExit: true},
	})
	if !errors.Is(err, io.EOF) || stats.Emitted != 2 || stats.Filtered != 1 || stats.Alerts != 1 {
		t.Fatalf("stats=%+v err=%v", stats, err)
	}
	if len(sink.events) != 2 || sink.events[0].EventType != events.DetectionAlert || sink.events[1].EventType != events.ProcessExit {
		t.Fatalf("unexpected outputs %+v", sink.events)
	}
}
