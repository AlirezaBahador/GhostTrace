// Package api exposes a bounded, read-only HTTP view over recorded GhostTrace
// JSONL. It is intentionally not a kernel health reporter or a SQLite store.
package api

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/AlirezaBahador/GhostTrace/internal/detection"
	"github.com/AlirezaBahador/GhostTrace/internal/eventio"
	"github.com/AlirezaBahador/GhostTrace/internal/filter"
	"github.com/AlirezaBahador/GhostTrace/pkg/events"
)

const (
	DefaultMaxFileBytes int64 = 64 << 20
	maxPageSize               = 200
	maxOffset                 = 100000
	maxProcesses              = 10000
)

type Server struct {
	EventsFile string
	RulesPath  string
	// Token is optional for a loopback-only deployment. Never pass tokens on
	// the command line: obtain them from a protected environment variable.
	Token        string
	MaxFileBytes int64
	concurrent   chan struct{}
	mux          *http.ServeMux
}

func New(eventsFile, rulesPath, token string, maxFileBytes int64) (*Server, error) {
	if eventsFile == "" || maxFileBytes < 1 {
		return nil, fmt.Errorf("events file and positive max file bytes required")
	}
	s := &Server{EventsFile: eventsFile, RulesPath: rulesPath, Token: token,
		MaxFileBytes: maxFileBytes, concurrent: make(chan struct{}, 4), mux: http.NewServeMux()}
	s.mux.HandleFunc("GET /api/v1/health", s.health)
	s.mux.HandleFunc("GET /api/v1/metrics", s.metrics)
	s.mux.HandleFunc("GET /api/v1/events", s.events)
	s.mux.HandleFunc("GET /api/v1/events/{id}", s.event)
	s.mux.HandleFunc("GET /api/v1/alerts", s.alerts)
	s.mux.HandleFunc("GET /api/v1/alerts/{id}", s.alert)
	s.mux.HandleFunc("GET /api/v1/processes", s.processes)
	s.mux.HandleFunc("GET /api/v1/processes/{id}", s.process)
	s.mux.HandleFunc("GET /api/v1/processes/{id}/tree", s.tree)
	s.mux.HandleFunc("GET /api/v1/rules", s.rules)
	s.mux.HandleFunc("GET /api/v1/stream", s.stream)
	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'")
	// Reject DNS-rebinding Host headers even on a listener bound to loopback.
	// A reviewed TLS proxy should preserve a loopback Host when forwarding.
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		fail(w, http.StatusForbidden, "invalid_host", "loopback Host required")
		return
	}
	if s.Token != "" {
		header := r.Header.Get("Authorization")
		// Bound work in constant-time comparison and suppress token logging.
		if len(header) != len("Bearer ")+len(s.Token) || !strings.HasPrefix(header, "Bearer ") ||
			subtle.ConstantTimeCompare([]byte(header[len("Bearer "):]), []byte(s.Token)) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			fail(w, http.StatusUnauthorized, "unauthorized", "Bearer token required")
			return
		}
	}
	select {
	case s.concurrent <- struct{}{}:
		defer func() { <-s.concurrent }()
	default:
		fail(w, http.StatusTooManyRequests, "busy", "too many concurrent requests")
		return
	}
	if r.URL.Path != "/api/v1/stream" {
		// Non-streaming endpoints must not be pinned indefinitely by a
		// slow client. The stream has independently bounded lifetime.
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(15 * time.Second))
	}
	s.mux.ServeHTTP(w, r)
}

func (s *Server) open() (*os.File, int64, error) {
	f, err := os.Open(s.EventsFile)
	if err != nil {
		return nil, 0, err
	}
	st, err := f.Stat()
	if err == nil && (!st.Mode().IsRegular() || st.Size() > s.MaxFileBytes) {
		err = fmt.Errorf("input must be a regular JSONL file <= %d bytes", s.MaxFileBytes)
	}
	if err != nil {
		_ = f.Close()
		return nil, 0, err
	}
	return f, st.Size(), nil
}

func (s *Server) visit(ctx context.Context, fn func(events.Event) (bool, error)) (int, error) {
	f, _, err := s.open()
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return eventio.Visit(ctx, f, fn)
}

// Fail closed on a missing, oversized or corrupt JSONL file. Don't expose
// server filesystem paths, validation data, or raw event content in errors.
func fail(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}

func parsePage(r *http.Request) (offset, limit int, err error) {
	q := r.URL.Query()
	offset = 0
	limit = 50
	for _, key := range []string{"offset", "limit"} {
		if len(q[key]) > 1 {
			return 0, 0, fmt.Errorf("duplicate %s", key)
		}
	}
	if v := q.Get("offset"); v != "" {
		offset, err = strconv.Atoi(v)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid offset")
		}
	}
	if v := q.Get("limit"); v != "" {
		limit, err = strconv.Atoi(v)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid limit")
		}
	}
	if offset < 0 || offset > maxOffset || limit < 1 || limit > maxPageSize {
		return 0, 0, fmt.Errorf("offset or limit out of bounds")
	}
	return
}

func single(q map[string][]string, key string) (string, error) {
	a := q[key]
	if len(a) > 1 {
		return "", fmt.Errorf("duplicate %q", key)
	}
	if len(a) == 0 {
		return "", nil
	}
	if len(a[0]) > 256 {
		return "", fmt.Errorf("%s too long", key)
	}
	return a[0], nil
}

func parseFilter(r *http.Request) (filter.Policy, error) {
	q := r.URL.Query()
	p := filter.Policy{}
	allowed := map[string]bool{"offset": true, "limit": true, "order": true, "comm": true, "uid": true, "type": true, "identity": true, "severity": true, "rule_id": true, "since": true, "until": true}
	for k := range q {
		if !allowed[k] {
			return p, fmt.Errorf("unknown parameter %q", k)
		}
	}
	for _, item := range []struct {
		key string
		dst *map[string]bool
	}{
		{"comm", &p.Comms}, {"type", &p.EventTypes}, {"identity", &p.Identities}, {"severity", &p.Severities}, {"rule_id", &p.RuleIDs},
	} {
		v, err := single(q, item.key)
		if err != nil {
			return p, err
		}
		if v != "" {
			*item.dst = map[string]bool{v: true}
		}
	}
	if v, err := single(q, "uid"); err != nil {
		return p, err
	} else if v != "" {
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return p, fmt.Errorf("invalid uid")
		}
		p.UIDs = map[uint32]bool{uint32(n): true}
	}
	for _, item := range []struct {
		key string
		dst *time.Time
	}{{"since", &p.Since}, {"until", &p.Until}} {
		v, err := single(q, item.key)
		if err != nil {
			return p, err
		}
		if v != "" {
			t, err := time.Parse(time.RFC3339Nano, v)
			if err != nil {
				return p, fmt.Errorf("invalid %s", item.key)
			}
			*item.dst = t
		}
	}
	return p, p.Validate()
}

func (s *Server) list(w http.ResponseWriter, r *http.Request, forceType string) {
	offset, limit, err := parsePage(r)
	if err != nil {
		fail(w, 400, "invalid_query", err.Error())
		return
	}
	p, err := parseFilter(r)
	if err != nil {
		fail(w, 400, "invalid_query", err.Error())
		return
	}
	if forceType != "" {
		if len(p.EventTypes) != 0 && !p.EventTypes[forceType] {
			fail(w, 400, "invalid_query", "type conflicts with endpoint")
			return
		}
		p.EventTypes = map[string]bool{forceType: true}
	}
	order, err := single(r.URL.Query(), "order")
	if err != nil || (order != "" && order != "asc" && order != "desc") {
		fail(w, 400, "invalid_query", "order must be asc or desc")
		return
	}
	items := make([]events.Event, 0, limit)
	total := 0
	_, err = s.visit(r.Context(), func(e events.Event) (bool, error) {
		if p.Match(e) {
			if order != "desc" && total >= offset && len(items) < limit {
				items = append(items, e)
			}
			total++
		}
		return true, nil
	})
	if err != nil {
		fail(w, 500, "source_unavailable", "recorded event file is missing, corrupt or too large")
		return
	}
	if order == "desc" && offset < total {
		// Two bounded scans preserve O(page-size) memory even for very large
		// source files. Append-only file updates may produce inconsistent pages;
		// caller should refresh on rotation or concurrent appends.
		start := total - offset - limit
		if start < 0 {
			start = 0
		}
		end := total - offset
		seen := 0
		_, err = s.visit(r.Context(), func(e events.Event) (bool, error) {
			if p.Match(e) {
				if seen >= start && seen < end {
					items = append(items, e)
				}
				seen++
			}
			return true, nil
		})
		if err != nil {
			fail(w, 500, "source_unavailable", "recorded event file changed or unavailable")
			return
		}
		for i, j := 0, len(items)-1; i < j; i, j = i+1, j-1 {
			items[i], items[j] = items[j], items[i]
		}
	}

	var next any
	if offset+len(items) < total {
		next = offset + len(items)
	}
	writeJSON(w, 200, map[string]any{"items": items, "total": total, "offset": offset, "limit": limit, "next_offset": next})
}
func (s *Server) events(w http.ResponseWriter, r *http.Request) { s.list(w, r, "") }
func (s *Server) alerts(w http.ResponseWriter, r *http.Request) { s.list(w, r, events.DetectionAlert) }

func (s *Server) get(w http.ResponseWriter, r *http.Request, alertOnly bool) {
	id := r.PathValue("id")
	if len(id) == 0 || len(id) > 128 {
		fail(w, 400, "invalid_id", "invalid id")
		return
	}
	var match events.Event
	_, err := s.visit(r.Context(), func(e events.Event) (bool, error) {
		if e.EventID == id && (!alertOnly || e.EventType == events.DetectionAlert) {
			if match.EventID == "" {
				match = e
			}
			return true, nil
		}
		return true, nil
	})
	if err != nil {
		fail(w, 500, "source_unavailable", "recorded events unavailable")
		return
	}
	if match.EventID == "" {
		fail(w, 404, "not_found", "event not found")
		return
	}
	writeJSON(w, 200, match)
}
func (s *Server) event(w http.ResponseWriter, r *http.Request) { s.get(w, r, false) }
func (s *Server) alert(w http.ResponseWriter, r *http.Request) { s.get(w, r, true) }

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	f, size, err := s.open()
	if err != nil {
		fail(w, 503, "source_unavailable", "recorded event file is unavailable")
		return
	}
	_ = f.Close()
	writeJSON(w, 200, map[string]any{"status": "ok", "mode": "recorded_jsonl", "agent_status": "unknown", "source_bytes": size})
}
func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	count, alerts := 0, 0
	n, err := s.visit(r.Context(), func(e events.Event) (bool, error) {
		count++
		if e.EventType == events.DetectionAlert {
			alerts++
		}
		return true, nil
	})
	_ = n
	if err != nil {
		fail(w, 500, "source_unavailable", "recorded events unavailable")
		return
	}
	writeJSON(w, 200, map[string]any{"recorded_events": count, "recorded_alerts": alerts, "scope": "recorded_jsonl_only", "kernel_drops": nil, "agent_cpu": nil})
}
func (s *Server) rules(w http.ResponseWriter, r *http.Request) {
	if s.RulesPath == "" {
		writeJSON(w, 200, map[string]any{"items": []any{}, "source": "not_configured"})
		return
	}
	rules, err := detection.Load(s.RulesPath)
	if err != nil {
		fail(w, 500, "rules_unavailable", "rules could not be loaded")
		return
	}
	type view struct {
		ID       string   `json:"id"`
		Name     string   `json:"name"`
		Enabled  bool     `json:"enabled"`
		Severity string   `json:"severity"`
		MITRE    []string `json:"mitre_techniques"`
	}
	items := make([]view, 0, len(rules))
	for _, r := range rules {
		items = append(items, view{r.ID, r.Name, r.Enabled, r.Severity, r.MITRE})
	}
	writeJSON(w, 200, map[string]any{"items": items, "source": "yaml"})
}

type ProcessView struct {
	Identity      string         `json:"identity"`
	Process       events.Process `json:"process"`
	LastEventID   string         `json:"last_event_id"`
	LastEventType string         `json:"last_event_type"`
	LastObserved  time.Time      `json:"last_observed"`
}

func (s *Server) processIndex(ctx context.Context) (map[string]ProcessView, error) {
	index := make(map[string]ProcessView)
	_, err := s.visit(ctx, func(e events.Event) (bool, error) {
		if e.EventType == events.DetectionAlert || e.Process.Identity == "" {
			return true, nil
		}
		id := e.Process.Identity
		if old, ok := index[id]; !ok || !e.Timestamp.Before(old.LastObserved) {
			index[id] = ProcessView{id, e.Process, e.EventID, e.EventType, e.Timestamp}
		}
		if len(index) > maxProcesses {
			return false, fmt.Errorf("too many distinct process identities")
		}
		return true, nil
	})
	return index, err
}
func (s *Server) processes(w http.ResponseWriter, r *http.Request) {
	offset, limit, err := parsePage(r)
	if err != nil {
		fail(w, 400, "invalid_query", err.Error())
		return
	}
	for key := range r.URL.Query() {
		if key != "offset" && key != "limit" {
			fail(w, 400, "invalid_query", "unknown parameter")
			return
		}
	}
	index, err := s.processIndex(r.Context())
	if err != nil {
		fail(w, 500, "source_unavailable", "process index unavailable")
		return
	}
	items := make([]ProcessView, 0, len(index))
	for _, v := range index {
		items = append(items, v)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].LastObserved.Equal(items[j].LastObserved) {
			return items[i].Identity < items[j].Identity
		}
		return items[i].LastObserved.After(items[j].LastObserved)
	})
	total := len(items)
	if offset >= total {
		items = []ProcessView{}
	} else {
		end := offset + limit
		if end > total {
			end = total
		}
		items = items[offset:end]
	}
	var next any
	if offset+len(items) < total {
		next = offset + len(items)
	}
	writeJSON(w, 200, map[string]any{"items": items, "total": total, "offset": offset, "limit": limit, "next_offset": next, "complete": false})
}
func (s *Server) process(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if len(id) > 256 || id == "" {
		fail(w, 400, "invalid_id", "invalid process identity")
		return
	}
	index, err := s.processIndex(r.Context())
	if err != nil {
		fail(w, 500, "source_unavailable", "process index unavailable")
		return
	}
	p, ok := index[id]
	if !ok {
		fail(w, 404, "not_found", "process identity not found")
		return
	}
	writeJSON(w, 200, p)
}
func (s *Server) tree(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if len(id) > 256 || id == "" {
		fail(w, 400, "invalid_id", "invalid process identity")
		return
	}
	index, err := s.processIndex(r.Context())
	if err != nil {
		fail(w, 500, "source_unavailable", "process index unavailable")
		return
	}
	if _, ok := index[id]; !ok {
		fail(w, 404, "not_found", "process identity not found")
		return
	}
	// Edges require the parent identity to ALSO occur in recorded telemetry.
	// A partial tree cannot prove that unobserved ancestors never existed.
	type edge struct {
		From string `json:"from"`
		To   string `json:"to"`
	}
	children := map[string][]string{}
	for k, v := range index {
		if v.Process.Parent != nil {
			p := v.Process.Parent.Identity
			if p != k && p != "" {
				if _, ok := index[p]; ok {
					children[p] = append(children[p], k)
				}
			}
		}
	}
	visited := map[string]bool{id: true}
	queue := []string{id}
	nodes := []ProcessView{}
	edges := []edge{}
	for len(queue) > 0 && len(nodes) < maxPageSize {
		current := queue[0]
		queue = queue[1:]
		nodes = append(nodes, index[current])
		sort.Strings(children[current])
		for _, child := range children[current] {
			if !visited[child] && len(visited) < maxPageSize {
				visited[child] = true
				queue = append(queue, child)
				edges = append(edges, edge{current, child})
			}
		}
	}
	writeJSON(w, 200, map[string]any{"root": id, "nodes": nodes, "edges": edges, "complete": false, "semantics": "observed_parent_relationships_only"})
}
