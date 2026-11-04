package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/ghosttrace/ghosttrace/internal/filter"
	"github.com/ghosttrace/ghosttrace/pkg/events"
	"strings"
	"testing"
	"time"
)

func queryEvent(t *testing.T, comm, kind string, uid uint32) string {
	t.Helper()
	e := events.Event{SchemaVersion: events.SchemaVersion, EventID: "id", EventType: kind, Timestamp: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC), TimestampSource: "userspace_receive", Source: "ebpf", Host: events.Host{Hostname: "host", BootID: "boot"}, Process: events.Process{PID: 3, TID: 3, UID: uid, Comm: comm}}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return string(b) + "\n"
}

func TestQuerySelectionAndLimit(t *testing.T) {
	in := queryEvent(t, "sh", events.ProcessExec, 1000) + queryEvent(t, "nginx", events.ProcessExec, 0) + queryEvent(t, "sh", events.ProcessExit, 1000) + queryEvent(t, "sh", events.ProcessExec, 1000)
	policy, err := parsePolicy("sh", "1000", "process_exec", "", "", "", "2026-11-04T12:00:00Z", "2026-11-04T12:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	count, err := Query(context.Background(), strings.NewReader(in), &out, policy, 0)
	if err != nil || count != 2 || strings.Count(out.String(), "\n") != 2 {
		t.Fatalf("count %d err %v output %s", count, err, out.String())
	}
	out.Reset()
	count, err = Query(context.Background(), strings.NewReader(in), &out, policy, 1)
	if err != nil || count != 1 || strings.Count(out.String(), "\n") != 1 {
		t.Fatalf("limit %d err %v", count, err)
	}
}

func TestQueryRejectsBadSelectorsAndInput(t *testing.T) {
	for _, tc := range []struct{ comm, uid, kind, identity, rule, severity, since, until string }{
		{uid: "-1"}, {uid: "abc"}, {uid: "01"}, {uid: "4294967296"}, {comm: "sh, sh"}, {kind: "network_connect"}, {severity: "severe"},
		{since: "tomorrow"}, {since: "2026-12-05T00:00:00Z", until: "2026-11-05T00:00:00Z"},
	} {
		if _, err := parsePolicy(tc.comm, tc.uid, tc.kind, tc.identity, tc.rule, tc.severity, tc.since, tc.until); err == nil {
			t.Fatalf("accepted %+v", tc)
		}
	}
	if _, err := Query(context.Background(), strings.NewReader("{}\n"), &bytes.Buffer{}, filter.Policy{}, 0); err == nil {
		t.Fatal("accepted invalid input")
	}
	if _, err := Query(context.Background(), strings.NewReader(""), &bytes.Buffer{}, filter.Policy{}, -1); err == nil {
		t.Fatal("negative limit accepted")
	}
}
