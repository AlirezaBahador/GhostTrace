// Package filter provides deterministic, exact-match, userspace filters.
// Matching is NOT kernel-side collection filtering or security enforcement.
package filter

import (
	"fmt"
	"time"

	"github.com/ghosttrace/ghosttrace/pkg/events"
)

type Policy struct {
	Comms      map[string]bool
	UIDs       map[uint32]bool
	EventTypes map[string]bool
	Identities map[string]bool
	RuleIDs    map[string]bool
	Severities map[string]bool
	Since      time.Time
	Until      time.Time
}

// Match requires every configured selector to match. The event timestamp is
// a userspace receipt/generation timestamp, never an exact kernel wall clock.
func (p Policy) Match(e events.Event) bool {
	if len(p.Comms) != 0 && !p.Comms[e.Process.Comm] {
		return false
	}
	if len(p.UIDs) != 0 && !p.UIDs[e.Process.UID] {
		return false
	}
	if len(p.EventTypes) != 0 && !p.EventTypes[e.EventType] {
		return false
	}
	if len(p.Identities) != 0 && !p.Identities[e.Process.Identity] {
		return false
	}
	if !p.Since.IsZero() && e.Timestamp.Before(p.Since) {
		return false
	}
	if !p.Until.IsZero() && e.Timestamp.After(p.Until) {
		return false
	}
	if len(p.RuleIDs) != 0 && (e.Detection == nil || !p.RuleIDs[e.Detection.RuleID]) {
		return false
	}
	if len(p.Severities) != 0 && (e.Detection == nil || !p.Severities[e.Detection.Severity]) {
		return false
	}
	return true
}

func (p Policy) Validate() error {
	if !p.Since.IsZero() && !p.Until.IsZero() && p.Since.After(p.Until) {
		return fmt.Errorf("since must be before or equal to until")
	}
	for kind := range p.EventTypes {
		switch kind {
		case events.ProcessExec, events.ProcessExit, events.DetectionAlert:
		default:
			return fmt.Errorf("unsupported event type %q", kind)
		}
	}
	for s := range p.Severities {
		switch s {
		case "info", "low", "medium", "high", "critical":
		default:
			return fmt.Errorf("unsupported severity %q", s)
		}
	}
	return nil
}
