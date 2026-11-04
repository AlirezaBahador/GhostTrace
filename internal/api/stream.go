package api

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/ghosttrace/ghosttrace/internal/eventio"
	"github.com/ghosttrace/ghosttrace/pkg/events"
)

// stream follows only bytes APPENDED after connection time (best effort).
// Unlike a WebSocket broker, this does not replay backlogged events; reconnects
// and log rotation may lose events. No claim of durable streaming delivery.
func (s *Server) stream(w http.ResponseWriter, r *http.Request) {
	if len(r.URL.Query()) != 0 {
		fail(w, 400, "invalid_query", "stream accepts no query parameters")
		return
	}
	f, _, err := s.open()
	if err != nil {
		fail(w, 503, "source_unavailable", "event file unavailable")
		return
	}
	defer f.Close()
	startInfo, err := f.Stat()
	if err != nil {
		fail(w, 503, "source_unavailable", "event file unavailable")
		return
	}
	if _, err = f.Seek(0, io.SeekEnd); err != nil {
		fail(w, 500, "source_unavailable", "cannot seek event file")
		return
	}
	controller := http.NewResponseController(w)
	// Short write deadlines prevent abandoned / slow clients from retaining
	// one of the bounded handler slots indefinitely.
	_ = controller.SetWriteDeadline(time.Now().Add(15 * time.Second))
	flusher, ok := w.(http.Flusher)
	if !ok {
		fail(w, 501, "not_supported", "response does not support streaming")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(200)
	if _, err = io.WriteString(w, ": ghosttrace live append stream; no historical replay\n\n"); err != nil {
		return
	}
	flusher.Flush()
	reader := bufio.NewReaderSize(f, 4096)
	var partial []byte
	poll := time.NewTicker(500 * time.Millisecond)
	defer poll.Stop()
	heartbeat := time.NewTicker(10 * time.Second)
	defer heartbeat.Stop()
	timeout := time.NewTimer(10 * time.Minute)
	defer timeout.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-timeout.C:
			return
		case <-heartbeat.C:
			_ = controller.SetWriteDeadline(time.Now().Add(15 * time.Second))
			if _, err = io.WriteString(w, ": heartbeat\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case <-poll.C:
			_ = controller.SetWriteDeadline(time.Now().Add(15 * time.Second))
			info, err := os.Stat(s.EventsFile)
			pos, _ := f.Seek(0, io.SeekCurrent)
			if err != nil || !os.SameFile(startInfo, info) || info.Size() < pos || info.Size() > s.MaxFileBytes {
				_, _ = io.WriteString(w, "event: reset\ndata: {\"reason\":\"source_changed\"}\n\n")
				flusher.Flush()
				return
			}
			for {
				part, err := reader.ReadBytes('\n')
				if len(part) > 0 {
					partial = append(partial, part...)
				}
				if len(partial) > eventio.MaxLine {
					_, _ = io.WriteString(w, "event: error\ndata: {\"reason\":\"record_too_large\"}\n\n")
					flusher.Flush()
					return
				}
				if err == io.EOF {
					break
				}
				if err != nil {
					return
				}
				if len(bytes.TrimSpace(partial)) == 0 {
					partial = nil
					continue
				}
				var event events.Event
				_, err = eventio.Visit(context.Background(), bytes.NewReader(partial), func(e events.Event) (bool, error) { event = e; return true, nil })
				partial = nil
				if err != nil {
					_, _ = io.WriteString(w, "event: error\ndata: {\"reason\":\"invalid_jsonl\"}\n\n")
					flusher.Flush()
					return
				}
				data, err := json.Marshal(event)
				if err != nil {
					return
				}
				if _, err = w.Write([]byte("event: event\ndata: ")); err != nil {
					return
				}
				if _, err = w.Write(data); err != nil {
					return
				}
				if _, err = io.WriteString(w, "\n\n"); err != nil {
					return
				}
				flusher.Flush()
			}
		}
	}
}
