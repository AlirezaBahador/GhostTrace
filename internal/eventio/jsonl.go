// Package eventio reads validated, versioned GhostTrace JSONL streams with
// fixed maximum record size. Data is operator-supplied, not fake telemetry.
package eventio

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/ghosttrace/ghosttrace/pkg/events"
)

const MaxLine = 1024 * 1024

// Visit decodes one JSON value per nonempty line and invokes fn in source
// order. It deliberately does not reorder events or assert event completeness.
// A false result from fn ends the scan early (remaining input is not checked).
func Visit(ctx context.Context, input io.Reader, fn func(events.Event) (bool, error)) (int, error) {
	if fn == nil {
		return 0, fmt.Errorf("event visitor is nil")
	}
	sc := bufio.NewScanner(input)
	sc.Buffer(make([]byte, 4096), MaxLine+1)
	visited := 0
	line := 0
	for sc.Scan() {
		line++
		if err := ctx.Err(); err != nil {
			return visited, err
		}
		data := bytes.TrimSpace(sc.Bytes())
		if len(data) == 0 {
			continue
		}
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		var e events.Event
		if err := dec.Decode(&e); err != nil {
			return visited, fmt.Errorf("line %d: decode event: %w", line, err)
		}
		var extra any
		if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
			return visited, fmt.Errorf("line %d: multiple JSON values", line)
		}
		if err := e.Validate(); err != nil {
			return visited, fmt.Errorf("line %d: %w", line, err)
		}
		visited++
		cont, err := fn(e)
		if err != nil {
			return visited, fmt.Errorf("line %d: visitor: %w", line, err)
		}
		if !cont {
			return visited, nil
		}
	}
	if err := sc.Err(); err != nil {
		return visited, fmt.Errorf("scan JSONL: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return visited, err
	}
	return visited, nil
}
