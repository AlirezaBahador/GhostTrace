package agent

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/ghosttrace/ghosttrace/internal/decoder"
	"github.com/ghosttrace/ghosttrace/pkg/events"
)

type fakeSource struct {
	ch   chan decoder.ProcessRecord
	once sync.Once
}

func (f *fakeSource) Read() (decoder.ProcessRecord, error) {
	r, ok := <-f.ch
	if !ok {
		return decoder.ProcessRecord{}, io.EOF
	}
	return r, nil
}
func (f *fakeSource) Stop() error { f.once.Do(func() { close(f.ch) }); return nil }

type fakeSink struct {
	events []events.Event
	err    error
}

func (s *fakeSink) Write(_ context.Context, e events.Event) error {
	if s.err != nil {
		return s.err
	}
	s.events = append(s.events, e)
	return nil
}

func TestRunShutdownUnblocksRead(t *testing.T) {
	source := &fakeSource{ch: make(chan decoder.ProcessRecord)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := Run(ctx, source, &fakeSink{}, events.Host{Hostname: "host", BootID: "boot"})
		done <- err
	}()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown deadlocked")
	}
}

func TestRunEmitsKernelRecord(t *testing.T) {
	source := &fakeSource{ch: make(chan decoder.ProcessRecord, 1)}
	sink := &fakeSink{}
	source.ch <- decoder.ProcessRecord{PID: 47, TID: 47, Kind: decoder.KindExec, Comm: "sleep"}
	source.Stop()
	stats, err := Run(context.Background(), source, sink, events.Host{Hostname: "host", BootID: "boot"})
	if err == nil || !errors.Is(err, io.EOF) {
		t.Fatalf("expected abnormal source close: %v", err)
	}
	if stats.Emitted != 1 || len(sink.events) != 1 || sink.events[0].Process.PID != 47 {
		t.Fatalf("bad stats %+v events %+v", stats, sink.events)
	}
}

func TestRunReturnsExporterError(t *testing.T) {
	source := &fakeSource{ch: make(chan decoder.ProcessRecord, 1)}
	source.ch <- decoder.ProcessRecord{PID: 1, TID: 1, Kind: decoder.KindExec}
	sink := &fakeSink{err: errors.New("broken pipe")}
	_, err := Run(context.Background(), source, sink, events.Host{Hostname: "host", BootID: "boot"})
	if err == nil {
		t.Fatal("expected exporter error")
	}
}
