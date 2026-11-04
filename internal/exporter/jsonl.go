package exporter

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"github.com/AlirezaBahador/GhostTrace/pkg/events"
)

// JSONL writes one complete event per line, synchronously. It has no unbounded
// in-memory backlog; slow output causes bounded kernel ring-buffer pressure.
type JSONL struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func NewJSONL(w io.Writer) *JSONL { return &JSONL{enc: json.NewEncoder(w)} }

func (w *JSONL) Write(ctx context.Context, e events.Event) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := e.Validate(); err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.enc.Encode(e); err != nil {
		return fmt.Errorf("write JSONL: %w", err)
	}
	return nil
}
