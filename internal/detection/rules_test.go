package detection

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AlirezaBahador/GhostTrace/pkg/events"
)

const exampleRule = `id: GT-001
name: Web Server Spawned Shell
description: Web server launched a shell.
enabled: true
severity: high
conditions:
  parent_process:
    - nginx
    - apache2
  child_process:
    - sh
    - bash
  exclude_parents:
    - safe-nginx
mitre:
  techniques:
    - T1059
    - T1059.004
actions:
  - alert
`

func TestParseAndMatch(t *testing.T) {
	r, err := ParseRule([]byte(exampleRule))
	if err != nil {
		t.Fatal(err)
	}
	if r.ID != "GT-001" || !r.Enabled || len(r.Conditions.ParentProcess) != 2 || len(r.MITRE) != 2 {
		t.Fatalf("bad rule %+v", r)
	}
	engine, err := New([]Rule{r})
	if err != nil {
		t.Fatal(err)
	}
	e := events.Event{SchemaVersion: events.SchemaVersion, EventID: "event-1", EventType: events.ProcessExec,
		Timestamp: time.Now().UTC(), TimestampSource: "userspace_receive",
		Host:    events.Host{Hostname: "host", BootID: "boot"},
		Process: events.Process{PID: 11, TID: 11, Comm: "sh", Parent: &events.Parent{PID: 10, Comm: "nginx"}}, Source: "ebpf"}
	alerts, err := engine.Evaluate(e)
	if err != nil || len(alerts) != 1 {
		t.Fatalf("expected alert: %d %v", len(alerts), err)
	}
	alert := alerts[0]
	if err := alert.Validate(); err != nil {
		t.Fatal(err)
	}
	if alert.EventType != events.DetectionAlert || alert.Detection.RuleID != "GT-001" ||
		alert.Detection.TriggeringEventIDs[0] != e.EventID || len(alert.Detection.MatchedConditions) != 2 ||
		alert.Detection.Severity != "high" || alert.Process.PID != 11 {
		t.Fatalf("bad alert %+v", alert)
	}
	e.Process.Parent = nil
	alerts, _ = engine.Evaluate(e)
	if len(alerts) != 0 {
		t.Fatal("matched when parent unknown")
	}
	e.Process.Parent = &events.Parent{Comm: "safe-nginx"}
	alerts, _ = engine.Evaluate(e)
	if len(alerts) != 0 {
		t.Fatal("exclusion failed")
	}
	e.Process.Parent = &events.Parent{Comm: "nginx"}
	e.EventType = events.ProcessExit
	alerts, _ = engine.Evaluate(e)
	if len(alerts) != 0 {
		t.Fatal("matched exit")
	}
	r.Enabled = false
	engine, _ = New([]Rule{r})
	e.EventType = events.ProcessExec
	alerts, _ = engine.Evaluate(e)
	if len(alerts) != 0 {
		t.Fatal("matched disabled rule")
	}
}

func TestRejectInvalidRules(t *testing.T) {
	tests := map[string]string{
		"unknown key":        exampleRule + "unknown: x\n",
		"duplicate":          exampleRule + "id: OTHER\n",
		"anchor":             strings.Replace(exampleRule, "- nginx", "- &server nginx", 1),
		"tag":                strings.Replace(exampleRule, "- nginx", "- !bad nginx", 1),
		"multiple documents": exampleRule + "---\n",
		"empty child":        strings.Replace(exampleRule, "    - sh\n    - bash\n", "", 1),
		"unsupported action": strings.Replace(exampleRule, "- alert", "- terminate", 1),
		"invalid MITRE":      strings.Replace(exampleRule, "T1059.004", "nope", 1),
		"invalid enabled":    strings.Replace(exampleRule, "enabled: true", "enabled: True", 1),
		"list level":         strings.Replace(exampleRule, "    - nginx", "  - nginx", 1),
		"unknown condition":  strings.Replace(exampleRule, "parent_process:", "world_process:", 1),
		"bad indent":         strings.Replace(exampleRule, "    - nginx", "   - nginx", 1),
		"too large":          exampleRule + strings.Repeat("A", MaxRuleBytes),
	}
	for name, src := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseRule([]byte(src)); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestDirectoryLoadingAndDuplicates(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.yaml"), []byte(exampleRule), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.yml"), []byte(strings.Replace(exampleRule, "GT-001", "GT-002", 1)), 0600); err != nil {
		t.Fatal(err)
	}
	rules, err := Load(dir)
	if err != nil || len(rules) != 2 || rules[0].ID != "GT-001" {
		t.Fatalf("bad load: %+v %v", rules, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.yml"), []byte(exampleRule), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("duplicate id allowed")
	}
}

func TestSingleChildRuleWithoutParent(t *testing.T) {
	src := `id: GT-011
name: Shell Watch
enabled: true
severity: low
conditions:
  child_process:
    - bash
actions:
  - alert
`
	r, err := ParseRule([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	engine, _ := New([]Rule{r})
	e := events.Event{SchemaVersion: events.SchemaVersion, EventID: "evt", EventType: events.ProcessExec, Timestamp: time.Now(), TimestampSource: "userspace_receive", Host: events.Host{Hostname: "h", BootID: "b"}, Process: events.Process{PID: 1, TID: 1, Comm: "bash"}, Source: "ebpf"}
	matches, err := engine.Evaluate(e)
	if err != nil || len(matches) != 1 {
		t.Fatalf("expected match without parent: %v %+v", err, matches)
	}
}
