// Package events contains the externally visible GhostTrace v1 event schema.
package events

import (
	"crypto/rand"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/AlirezaBahador/GhostTrace/internal/decoder"
)

const SchemaVersion = "1.0"

const (
	ProcessExec    = "process_exec"
	ProcessExit    = "process_exit"
	DetectionAlert = "detection_alert"
)

type Host struct {
	Hostname string `json:"hostname"`
	BootID   string `json:"boot_id"`
}

// Parent represents a procfs-observed parent. It is optional and may differ
// from the parent at kernel event time due to reparenting or PID reuse.
type Parent struct {
	PID            uint32 `json:"pid"`
	Comm           string `json:"comm"`
	Identity       string `json:"identity,omitempty"`
	StartTimeTicks uint64 `json:"start_time_ticks,omitempty"`
}

type Process struct {
	Identity       string  `json:"identity,omitempty"`
	IdentitySource string  `json:"identity_source,omitempty"`
	StartTimeTicks uint64  `json:"start_time_ticks,omitempty"`
	PPID           *uint32 `json:"ppid,omitempty"`
	Executable     string  `json:"executable,omitempty"`
	Parent         *Parent `json:"parent,omitempty"`
	PID            uint32  `json:"pid"`
	TID            uint32  `json:"tid"`
	UID            uint32  `json:"uid"`
	GID            uint32  `json:"gid"`
	Comm           string  `json:"comm"`
}

// Detection contains evidence for a specific rule match, not a risk score.
type Detection struct {
	RuleID             string   `json:"rule_id"`
	RuleName           string   `json:"rule_name"`
	Severity           string   `json:"severity"`
	TriggeringEventIDs []string `json:"triggering_event_ids"`
	MatchedConditions  []string `json:"matched_conditions"`
	MITRETechniques    []string `json:"mitre_techniques,omitempty"`
}

type Event struct {
	SchemaVersion     string     `json:"schema_version"`
	EventID           string     `json:"event_id"`
	EventType         string     `json:"event_type"`
	Timestamp         time.Time  `json:"timestamp"`
	TimestampSource   string     `json:"timestamp_source"`
	KernelMonotonicNS uint64     `json:"kernel_monotonic_ns,omitempty"`
	Host              Host       `json:"host"`
	Process           Process    `json:"process"`
	Detection         *Detection `json:"detection,omitempty"`
	Source            string     `json:"source"`
}

func LocalHost() (Host, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return Host{}, fmt.Errorf("hostname: %w", err)
	}
	bootID, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return Host{}, fmt.Errorf("read host boot_id: %w", err)
	}
	h := Host{Hostname: hostname, BootID: strings.TrimSpace(string(bootID))}
	if h.Hostname == "" || h.BootID == "" {
		return Host{}, fmt.Errorf("host identity is incomplete")
	}
	return h, nil
}

// FromRecord explicitly timestamps at userspace receipt, not at the kernel
// event time. The kernel monotonic timestamp is preserved separately.
func FromRecord(r decoder.ProcessRecord, host Host, receivedAt time.Time) (Event, error) {
	eventType := ""
	switch r.Kind {
	case decoder.KindExec:
		eventType = ProcessExec
	case decoder.KindExit:
		eventType = ProcessExit
	default:
		return Event{}, fmt.Errorf("unsupported event kind %d", r.Kind)
	}
	id, err := newID()
	if err != nil {
		return Event{}, err
	}
	e := Event{
		SchemaVersion: SchemaVersion, EventID: id, EventType: eventType,
		Timestamp: receivedAt.UTC(), TimestampSource: "userspace_receive",
		KernelMonotonicNS: r.MonotonicNS, Host: host,
		Process: Process{PID: r.PID, TID: r.TID, UID: r.UID, GID: r.GID, Comm: r.Comm},
		Source:  "ebpf",
	}
	if err := e.Validate(); err != nil {
		return Event{}, err
	}
	return e, nil
}

func (e Event) Validate() error {
	if e.SchemaVersion != SchemaVersion || e.EventID == "" || e.Timestamp.IsZero() ||
		(e.TimestampSource != "userspace_receive" && e.TimestampSource != "detection_generated") ||
		e.Host.Hostname == "" || e.Host.BootID == "" || e.Process.PID == 0 || e.Process.TID == 0 ||
		(e.EventType != ProcessExec && e.EventType != ProcessExit && e.EventType != DetectionAlert) {
		return fmt.Errorf("invalid event schema fields")
	}
	if e.EventType == DetectionAlert {
		if e.TimestampSource != "detection_generated" || e.Source != "detection" || e.Detection == nil || e.Detection.RuleID == "" ||
			e.Detection.RuleName == "" || e.Detection.Severity == "" ||
			len(e.Detection.TriggeringEventIDs) == 0 || len(e.Detection.MatchedConditions) == 0 {
			return fmt.Errorf("invalid detection alert")
		}
	} else if e.TimestampSource != "userspace_receive" || e.Source != "ebpf" || e.Detection != nil {
		return fmt.Errorf("invalid event schema fields")
	}
	return nil
}

// NewDetectionAlert converts a positive rule match into a structured, linked
// alert. The event timestamp describes when the rule matched in userspace.
func NewDetectionAlert(trigger Event, result Detection, now time.Time) (Event, error) {
	if trigger.EventType != ProcessExec {
		return Event{}, fmt.Errorf("detection trigger must be a process exec event")
	}
	id, err := newID()
	if err != nil {
		return Event{}, err
	}
	alert := Event{
		SchemaVersion: SchemaVersion, EventID: id, EventType: DetectionAlert,
		Timestamp: now.UTC(), TimestampSource: "detection_generated",
		Host:    trigger.Host,
		Process: trigger.Process, Detection: &result, Source: "detection",
	}
	if err := alert.Validate(); err != nil {
		return Event{}, err
	}
	return alert, nil
}

func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("event ID entropy: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
