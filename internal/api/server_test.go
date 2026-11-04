package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghosttrace/ghosttrace/pkg/events"
)

// These are labeled unit-test fixtures, NEVER kernel-originated telemetry.
func fixture(id, kind, ident, parent string, when time.Time) events.Event {
	e := events.Event{SchemaVersion: events.SchemaVersion, EventID: id, EventType: kind,
		Timestamp: when, TimestampSource: "userspace_receive", Source: "ebpf",
		Host:    events.Host{Hostname: "unit-test", BootID: "unit-boot"},
		Process: events.Process{PID: 100, TID: 100, Comm: "sh", UID: 1000, GID: 1000, Identity: ident}}
	if parent != "" {
		e.Process.Parent = &events.Parent{PID: 99, Comm: "nginx", Identity: parent}
	}
	if kind == events.DetectionAlert {
		e.Source = "detection"
		e.TimestampSource = "detection_generated"
		e.Detection = &events.Detection{RuleID: "GT-001", RuleName: "test", Severity: "high",
			TriggeringEventIDs: []string{"id-1"}, MatchedConditions: []string{"process.comm=sh"}}
	}
	return e
}
func testServer(t *testing.T) (*Server, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "events.jsonl")
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	records := []events.Event{fixture("id-1", events.ProcessExec, "boot:99:1", "", now), fixture("id-2", events.ProcessExec, "boot:100:2", "boot:99:1", now.Add(time.Second)), fixture("id-3", events.DetectionAlert, "boot:100:2", "boot:99:1", now.Add(2*time.Second))}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range records {
		if err := json.NewEncoder(f).Encode(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := New(path, "", "", DefaultMaxFileBytes)
	if err != nil {
		t.Fatal(err)
	}
	return s, path
}
func call(s *Server, method, path string, headers map[string]string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(method, path, nil)
	r.Host = "127.0.0.1:7766"
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	s.ServeHTTP(w, r)
	return w
}
func TestEventsPaginationAndFiltering(t *testing.T) {
	s, _ := testServer(t)
	w := call(s, "GET", "/api/v1/events?limit=1&offset=1", nil)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	var page struct {
		Items      []events.Event `json:"items"`
		Total      int            `json:"total"`
		NextOffset *int           `json:"next_offset"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if page.Total != 3 || len(page.Items) != 1 || page.Items[0].EventID != "id-2" || *page.NextOffset != 2 {
		t.Fatal(page)
	}
	w = call(s, "GET", "/api/v1/events?comm=sh&uid=1000&type=process_exec", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"total":2`) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	w = call(s, "GET", "/api/v1/alerts?severity=high", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"total":1`) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	w = call(s, "GET", "/api/v1/events/id-2", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"event_id":"id-2"`) {
		t.Fatal(w.Code, w.Body)
	}
	w = call(s, "GET", "/api/v1/alerts/id-2", nil)
	if w.Code != 404 {
		t.Fatalf("expected 404 got %d", w.Code)
	}
	for _, q := range []string{"?limit=999", "?offset=-1", "?type=invalid", "?severity=very-high", "?since=yesterday", "?unexpected=ok", "?uid=invalid", "?uid=1&uid=2", "?type=process_exit"} {
		path := "/api/v1/alerts" + q
		if q == "?type=process_exit" || q == "?uid=1&uid=2" {
			path = "/api/v1/alerts" + q
		}
		w = call(s, "GET", path, nil)
		if w.Code != 400 {
			t.Errorf("%s expected 400 got %d: %s", path, w.Code, w.Body)
		}
	}
}
func TestIdentityTreeAndMetrics(t *testing.T) {
	s, _ := testServer(t)
	for url, expected := range map[string]string{
		"/api/v1/processes":                "\"total\":2",
		"/api/v1/processes/boot:100:2":     "\"identity\":\"boot:100:2\"",
		"/api/v1/processes/boot:99:1/tree": "\"complete\":false",
		"/api/v1/metrics":                  "\"recorded_alerts\":1",
		"/api/v1/health":                   "\"agent_status\":\"unknown\"",
		"/api/v1/rules":                    "\"items\":[]",
	} {
		w := call(s, "GET", url, nil)
		if w.Code != 200 || !strings.Contains(w.Body.String(), expected) {
			t.Errorf("%s => %d %s", url, w.Code, w.Body)
		}
	}
	w := call(s, "GET", "/api/v1/processes/boot:99:1/tree", nil)
	if !strings.Contains(w.Body.String(), `"from":"boot:99:1"`) || !strings.Contains(w.Body.String(), `"to":"boot:100:2"`) {
		t.Fatalf("missing observed link %s", w.Body)
	}
}
func TestAuthAndSourceErrors(t *testing.T) {
	s, path := testServer(t)
	s.Token = "this-is-a-test-token-123"
	for _, h := range []map[string]string{nil, {"Authorization": "Bearer wrong"}, {"Authorization": "Basic this-is-a-test-token-123"}} {
		w := call(s, "GET", "/api/v1/events", h)
		if w.Code != 401 || !strings.Contains(w.Body.String(), "unauthorized") {
			t.Fatal(w.Code, w.Body)
		}
		if strings.Contains(w.Body.String(), s.Token) {
			t.Fatal("secret echoed")
		}
	}
	w := call(s, "GET", "/api/v1/events", map[string]string{"Authorization": "Bearer " + s.Token})
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	s.Token = ""
	if err := os.WriteFile(path, []byte("not-json\n"), 0600); err != nil {
		t.Fatal(err)
	}
	w = call(s, "GET", "/api/v1/events", nil)
	if w.Code != 500 || strings.Contains(w.Body.String(), "not-json") {
		t.Fatal(w.Code, w.Body)
	}
	if err := os.WriteFile(path, bytes.Repeat([]byte{' '}, 300), 0600); err != nil {
		t.Fatal(err)
	}
	s.MaxFileBytes = 200
	w = call(s, "GET", "/api/v1/events", nil)
	if w.Code != 500 {
		t.Fatal(w.Code, w.Body)
	}
}
func TestCancelAndConcurrencyLimit(t *testing.T) {
	s, _ := testServer(t)
	for i := 0; i < cap(s.concurrent); i++ {
		s.concurrent <- struct{}{}
	}
	w := call(s, "GET", "/api/v1/health", nil)
	if w.Code != 429 {
		t.Fatal(w.Code, w.Body)
	}
	for i := 0; i < cap(s.concurrent); i++ {
		<-s.concurrent
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest("GET", "/api/v1/events", nil).WithContext(ctx)
	req.Host = "127.0.0.1:7766"
	w = httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != 500 {
		t.Fatalf("cancel returned %d", w.Code)
	}
}
func TestSSEAppendedRealFileBytesInUnitTest(t *testing.T) {
	s, path := testServer(t)
	srv := httptest.NewServer(s)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/api/v1/stream", nil)
	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 || res.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatal(res.Status, res.Header)
	}
	stream := make(chan string, 1)
	go func() {
		b := make([]byte, 4096)
		var total bytes.Buffer
		for {
			n, err := res.Body.Read(b)
			if n > 0 {
				total.Write(b[:n])
				if strings.Contains(total.String(), "event: event") {
					stream <- total.String()
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	e := fixture("id-stream", events.ProcessExec, "boot:500:3", "", time.Now().UTC())
	// Split writes exercise the partial-line handling.
	raw, _ := json.Marshal(e)
	if _, err = f.Write(raw[:len(raw)/2]); err != nil {
		t.Fatal(err)
	}
	time.Sleep(600 * time.Millisecond)
	if _, err = f.Write(append(raw[len(raw)/2:], '\n')); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	select {
	case got := <-stream:
		if !strings.Contains(got, `"event_id":"id-stream"`) {
			t.Fatal(got)
		}
	case <-ctx.Done():
		t.Fatal(fmt.Errorf("SSE append not observed: %w", ctx.Err()))
	}
}

func TestDescendingRecordedOrder(t *testing.T) {
	s, _ := testServer(t)
	for _, tc := range []struct {
		query, first          string
		length, total, status int
	}{
		{"order=desc&limit=2", "id-3", 2, 3, 200},
		{"order=desc&limit=1&offset=1", "id-2", 1, 3, 200},
		{"order=desc&limit=10&offset=2", "id-1", 1, 3, 200},
		{"order=desc&limit=10&offset=3", "", 0, 3, 200},
		{"order=invalid", "", 0, 0, 400},
	} {
		w := call(s, "GET", "/api/v1/events?"+tc.query, nil)
		if w.Code != tc.status {
			t.Fatalf("%s code %d: %s", tc.query, w.Code, w.Body)
		}
		if tc.status != 200 {
			continue
		}
		var page struct {
			Items []events.Event `json:"items"`
			Total int            `json:"total"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		if page.Total != tc.total || len(page.Items) != tc.length || tc.length > 0 && page.Items[0].EventID != tc.first {
			t.Fatalf("%s: %#v", tc.query, page)
		}
	}
}

func TestDNSRebindingHostRejected(t *testing.T) {
	s, _ := testServer(t)
	r := httptest.NewRequest("GET", "http://evil.example/api/v1/events", nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("Host was accepted: %d %s", w.Code, w.Body)
	}
}
