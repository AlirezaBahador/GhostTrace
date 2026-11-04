package filter

import (
	"testing"
	"time"

	"github.com/ghosttrace/ghosttrace/pkg/events"
)

func TestPolicyMatchingANDAndAlertFields(t *testing.T) {
	e := events.Event{EventType: events.ProcessExec, Timestamp: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC), Process: events.Process{Comm: "sh", UID: 33, Identity: "boot:88:4"}}
	p := Policy{Comms: map[string]bool{"sh": true}, UIDs: map[uint32]bool{33: true}, EventTypes: map[string]bool{events.ProcessExec: true}, Identities: map[string]bool{"boot:88:4": true}, Since: e.Timestamp, Until: e.Timestamp}
	if err := p.Validate(); err != nil || !p.Match(e) {
		t.Fatalf("valid filter failed: %v", err)
	}
	e.Process.UID = 0
	if p.Match(e) {
		t.Fatal("should require both comm and uid")
	}
	e.Process.UID = 33
	e.Timestamp = e.Timestamp.Add(-time.Nanosecond)
	if p.Match(e) {
		t.Fatal("matched before since")
	}
	e.Timestamp = e.Timestamp.Add(2 * time.Nanosecond)
	if p.Match(e) {
		t.Fatal("matched after until")
	}
	e.Timestamp = e.Timestamp.Add(-time.Nanosecond)
	p.RuleIDs = map[string]bool{"GT-001": true}
	if p.Match(e) {
		t.Fatal("non alert matched rule id")
	}
	e.EventType = events.DetectionAlert
	e.Detection = &events.Detection{RuleID: "GT-001", Severity: "high"}
	p.EventTypes = nil
	p.Severities = map[string]bool{"high": true}
	if !p.Match(e) {
		t.Fatal("alert match failed")
	}
	e.Detection.Severity = "low"
	if p.Match(e) {
		t.Fatal("mismatched severity")
	}
}

func TestPolicyRejectsUnsupported(t *testing.T) {
	for _, p := range []Policy{
		{EventTypes: map[string]bool{"file_read": true}},
		{Severities: map[string]bool{"urgent": true}},
		{Since: time.Now().Add(time.Hour), Until: time.Now()},
	} {
		if p.Validate() == nil {
			t.Fatalf("accepted %+v", p)
		}
	}
}
