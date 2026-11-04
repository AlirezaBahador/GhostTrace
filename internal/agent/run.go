package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/ghosttrace/ghosttrace/internal/decoder"
	"github.com/ghosttrace/ghosttrace/internal/filter"
	"github.com/ghosttrace/ghosttrace/pkg/events"
)

// Source can be implemented by a kernel ring reader or a test fixture.
// Stop unblocks any pending Read without closing kernel resources prematurely.
type Source interface {
	Read() (decoder.ProcessRecord, error)
	Stop() error
}

type Sink interface {
	Write(context.Context, events.Event) error
}

type Enricher interface{ Enrich(*events.Event) }
type Detector interface {
	Evaluate(events.Event) ([]events.Event, error)
}

type Options struct {
	Enricher Enricher
	Detector Detector
	// IncludeComm filters ONLY ordinary telemetry export, after enrichment
	// and rule evaluation. Alerts are always exported. Empty means all.
	IncludeComm      map[string]bool
	IncludeUID       map[uint32]bool
	IncludeEventType map[string]bool
}

type Stats struct {
	Emitted  uint64
	Alerts   uint64
	Filtered uint64
}

func Run(ctx context.Context, source Source, sink Sink, host events.Host) (Stats, error) {
	return RunWithOptions(ctx, source, sink, host, Options{})
}

// RunWithOptions processes one ring reader synchronously. Output backpressure
// propagates to the kernel buffer; no unbounded queue is introduced.
func RunWithOptions(ctx context.Context, source Source, sink Sink, host events.Host, opts Options) (Stats, error) {
	var stats Stats
	stop := context.AfterFunc(ctx, func() { _ = source.Stop() })
	defer stop()
	for {
		record, err := source.Read()
		if err != nil {
			if ctx.Err() != nil {
				return stats, nil
			}
			if errors.Is(err, io.EOF) {
				return stats, fmt.Errorf("event source closed unexpectedly: %w", err)
			}
			return stats, fmt.Errorf("read kernel event: %w", err)
		}
		if ctx.Err() != nil {
			return stats, nil
		}
		e, err := events.FromRecord(record, host, time.Now())
		if err != nil {
			return stats, fmt.Errorf("convert kernel event: %w", err)
		}
		if opts.Enricher != nil {
			opts.Enricher.Enrich(&e)
		}
		var alerts []events.Event
		if opts.Detector != nil {
			alerts, err = opts.Detector.Evaluate(e)
			if err != nil {
				return stats, fmt.Errorf("detect event: %w", err)
			}
		}
		if !(filter.Policy{Comms: opts.IncludeComm, UIDs: opts.IncludeUID, EventTypes: opts.IncludeEventType}).Match(e) {
			stats.Filtered++
		} else {
			if err := sink.Write(ctx, e); err != nil {
				if ctx.Err() != nil {
					return stats, nil
				}
				return stats, fmt.Errorf("export event: %w", err)
			}
			stats.Emitted++
		}
		if ctx.Err() != nil {
			return stats, nil
		}
		for _, alert := range alerts {
			if err := sink.Write(ctx, alert); err != nil {
				if ctx.Err() != nil {
					return stats, nil
				}
				return stats, fmt.Errorf("export alert: %w", err)
			}
			stats.Emitted++
			stats.Alerts++
		}
	}
}
