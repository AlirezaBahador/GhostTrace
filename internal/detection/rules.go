// Package detection implements a deliberately restricted, fail-closed YAML
// rule subset. It does not accept arbitrary YAML tags, anchors, expressions,
// or unimplemented actions. See docs/DETECTION.md for the exact grammar.
package detection

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/AlirezaBahador/GhostTrace/pkg/events"
)

const MaxRuleBytes = 64 * 1024
const MaxRules = 128

var (
	nameRE  = regexp.MustCompile(`^[A-Za-z0-9_.+/-]{1,64}$`)
	idRE    = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{1,63}$`)
	mitreRE = regexp.MustCompile(`^T[0-9]{4}(\.[0-9]{3})?$`)
)

type Conditions struct {
	ParentProcess   []string
	ChildProcess    []string
	ExcludeParents  []string
	ExcludeChildren []string
}

type Rule struct {
	ID          string
	Name        string
	Description string
	Enabled     bool
	Severity    string
	Conditions  Conditions
	MITRE       []string
	Actions     []string
}

func (r Rule) Validate() error {
	if !idRE.MatchString(r.ID) || strings.TrimSpace(r.Name) == "" || len(r.Name) > 128 || len(r.Description) > 2048 {
		return fmt.Errorf("invalid rule id/name/description")
	}
	switch r.Severity {
	case "info", "low", "medium", "high", "critical":
	default:
		return fmt.Errorf("rule %s: invalid severity %q", r.ID, r.Severity)
	}
	if len(r.Conditions.ChildProcess) == 0 {
		return fmt.Errorf("rule %s: child_process is required", r.ID)
	}
	for _, set := range [][]string{r.Conditions.ChildProcess, r.Conditions.ParentProcess, r.Conditions.ExcludeParents, r.Conditions.ExcludeChildren} {
		if len(set) > 64 {
			return fmt.Errorf("rule %s: too many names in a condition", r.ID)
		}
		for _, name := range set {
			if !nameRE.MatchString(name) {
				return fmt.Errorf("rule %s: invalid process name %q", r.ID, name)
			}
		}
	}
	if len(r.Actions) != 1 || r.Actions[0] != "alert" {
		return fmt.Errorf("rule %s: only actions: [alert] is currently implemented", r.ID)
	}
	for _, t := range r.MITRE {
		if !mitreRE.MatchString(t) {
			return fmt.Errorf("rule %s: invalid MITRE technique %q", r.ID, t)
		}
	}
	return nil
}

// ParseRule accepts exactly one document, with two-space indentation and
// scalar or block-sequence values. Unknown fields and duplicate keys fail.
func ParseRule(data []byte) (Rule, error) {
	if len(data) > MaxRuleBytes {
		return Rule{}, fmt.Errorf("rule file exceeds %d bytes", MaxRuleBytes)
	}
	var r Rule
	seen := map[string]bool{}
	section, list := "", ""
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 4096), MaxRuleBytes+1)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		text := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(text) == "" || strings.HasPrefix(strings.TrimSpace(text), "#") {
			continue
		}
		if strings.ContainsRune(text, '\t') || strings.HasPrefix(text, "---") || strings.HasPrefix(text, "...") {
			return Rule{}, fmt.Errorf("line %d: unsupported YAML construct", lineNo)
		}
		spaces := len(text) - len(strings.TrimLeft(text, " "))
		if spaces != 0 && spaces != 2 && spaces != 4 {
			return Rule{}, fmt.Errorf("line %d: invalid indentation", lineNo)
		}
		trimmed := text[spaces:]
		if strings.HasPrefix(trimmed, "- ") {
			value, err := scalar(strings.TrimSpace(trimmed[2:]))
			if err != nil {
				return Rule{}, fmt.Errorf("line %d: %w", lineNo, err)
			}
			if spaces == 2 && section == "actions" {
				r.Actions = append(r.Actions, value)
			} else if spaces == 4 && section == "conditions" {
				switch list {
				case "parent_process":
					r.Conditions.ParentProcess = append(r.Conditions.ParentProcess, value)
				case "child_process":
					r.Conditions.ChildProcess = append(r.Conditions.ChildProcess, value)
				case "exclude_parents":
					r.Conditions.ExcludeParents = append(r.Conditions.ExcludeParents, value)
				case "exclude_children":
					r.Conditions.ExcludeChildren = append(r.Conditions.ExcludeChildren, value)
				default:
					return Rule{}, fmt.Errorf("line %d: list item outside known list", lineNo)
				}
			} else if spaces == 4 && section == "mitre" && list == "techniques" {
				r.MITRE = append(r.MITRE, value)
			} else {
				return Rule{}, fmt.Errorf("line %d: list item at invalid depth", lineNo)
			}
			continue
		}
		parts := strings.SplitN(trimmed, ":", 2)
		if len(parts) != 2 {
			return Rule{}, fmt.Errorf("line %d: expected key: value", lineNo)
		}
		key, value := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		var scope string
		if spaces == 0 {
			section, list, scope = "", "", "root"
		}
		if spaces == 2 {
			if section != "conditions" && section != "mitre" {
				return Rule{}, fmt.Errorf("line %d: nested mapping not supported here", lineNo)
			}
			scope = section
		}
		if spaces == 4 {
			return Rule{}, fmt.Errorf("line %d: nested scalar unsupported", lineNo)
		}
		lookup := scope + "." + key
		if seen[lookup] {
			return Rule{}, fmt.Errorf("line %d: duplicate key %q", lineNo, key)
		}
		seen[lookup] = true
		if spaces == 0 {
			switch key {
			case "id", "name", "description", "enabled", "severity":
				v, err := scalar(value)
				if err != nil {
					return Rule{}, fmt.Errorf("line %d: %w", lineNo, err)
				}
				switch key {
				case "id":
					r.ID = v
				case "name":
					r.Name = v
				case "description":
					r.Description = v
				case "severity":
					r.Severity = v
				case "enabled":
					if v != "true" && v != "false" {
						return Rule{}, fmt.Errorf("line %d: enabled must be true or false", lineNo)
					}
					r.Enabled = v == "true"
				}
			case "conditions", "mitre", "actions":
				if value != "" {
					return Rule{}, fmt.Errorf("line %d: %s must use an indented block", lineNo, key)
				}
				section = key
			default:
				return Rule{}, fmt.Errorf("line %d: unknown field %q", lineNo, key)
			}
		} else {
			if value != "" {
				return Rule{}, fmt.Errorf("line %d: list must use an indented block", lineNo)
			}
			if section == "conditions" {
				switch key {
				case "parent_process", "child_process", "exclude_parents", "exclude_children":
				default:
					return Rule{}, fmt.Errorf("line %d: unknown condition %q", lineNo, key)
				}
			} else if key != "techniques" {
				return Rule{}, fmt.Errorf("line %d: unknown MITRE field", lineNo)
			}
			list = key
		}
	}
	if err := sc.Err(); err != nil {
		return Rule{}, fmt.Errorf("scan rule: %w", err)
	}
	for _, required := range []string{"root.id", "root.name", "root.enabled", "root.severity", "root.conditions", "root.actions"} {
		if !seen[required] {
			return Rule{}, fmt.Errorf("missing required field %s", required)
		}
	}
	if err := r.Validate(); err != nil {
		return Rule{}, err
	}
	return r, nil
}

func scalar(s string) (string, error) {
	if s == "" || len(s) > 2048 {
		return "", fmt.Errorf("empty or oversized scalar")
	}
	if strings.ContainsAny(s, "#{}[]&*!|<>`\\") {
		return "", fmt.Errorf("unsupported YAML scalar")
	}
	if strings.HasPrefix(s, "\"") || strings.HasPrefix(s, "'") {
		if len(s) < 2 || s[len(s)-1] != s[0] {
			return "", fmt.Errorf("unterminated quoted scalar")
		}
		if s[0] == '\'' {
			return strings.ReplaceAll(s[1:len(s)-1], "''", "'"), nil
		}
		return strings.Trim(s, "\""), nil // double-quoted escape sequences not supported
	}
	if strings.ContainsRune(s, '"') || strings.ContainsRune(s, '\'') {
		return "", fmt.Errorf("quote must enclose entire scalar")
	}
	return s, nil
}

// Load reads a single YAML file or a directory of *.yaml/*.yml rules.
// Loading is atomic: any invalid rule prevents the engine from starting.
func Load(path string) ([]Rule, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("rules path: %w", err)
	}
	paths := []string{path}
	if info.IsDir() {
		paths = nil
		entries, err := os.ReadDir(path)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if filepath.Ext(e.Name()) == ".yaml" || filepath.Ext(e.Name()) == ".yml" {
				paths = append(paths, filepath.Join(path, e.Name()))
			}
		}
		sort.Strings(paths)
	}
	if len(paths) == 0 || len(paths) > MaxRules {
		return nil, fmt.Errorf("rules count must be between 1 and %d", MaxRules)
	}
	var rules []Rule
	ids := make(map[string]bool)
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			return nil, err
		}
		data, readErr := io.ReadAll(io.LimitReader(f, MaxRuleBytes+1))
		closeErr := f.Close()
		if readErr != nil {
			return nil, readErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		r, err := ParseRule(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		if ids[r.ID] {
			return nil, fmt.Errorf("duplicate rule id %q", r.ID)
		}
		ids[r.ID] = true
		rules = append(rules, r)
	}
	return rules, nil
}

// Engine matches current process execution events; it does not claim
// time-window, file, network, or multi-event correlation.
type Engine struct{ rules []Rule }

func New(rules []Rule) (*Engine, error) {
	ids := make(map[string]bool)
	for _, r := range rules {
		if err := r.Validate(); err != nil {
			return nil, err
		}
		if ids[r.ID] {
			return nil, fmt.Errorf("duplicate rule %s", r.ID)
		}
		ids[r.ID] = true
	}
	return &Engine{rules: append([]Rule(nil), rules...)}, nil
}

func includes(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

func (d *Engine) Evaluate(e events.Event) ([]events.Event, error) {
	if e.EventType != events.ProcessExec {
		return nil, nil
	}
	var alerts []events.Event
	for _, r := range d.rules {
		if !r.Enabled || !includes(r.Conditions.ChildProcess, e.Process.Comm) || includes(r.Conditions.ExcludeChildren, e.Process.Comm) {
			continue
		}
		matched := []string{"process.comm=" + e.Process.Comm}
		if len(r.Conditions.ParentProcess) > 0 {
			// Parent from procfs is optional; fail closed instead of guessing.
			if e.Process.Parent == nil || !includes(r.Conditions.ParentProcess, e.Process.Parent.Comm) {
				continue
			}
			matched = append(matched, "process.parent.comm="+e.Process.Parent.Comm)
		}
		if len(r.Conditions.ExcludeParents) > 0 && e.Process.Parent == nil {
			// Missing enrichment must never bypass a configured allowlist.
			continue
		}
		if e.Process.Parent != nil && includes(r.Conditions.ExcludeParents, e.Process.Parent.Comm) {
			continue
		}
		result := events.Detection{RuleID: r.ID, RuleName: r.Name, Severity: r.Severity,
			TriggeringEventIDs: []string{e.EventID}, MatchedConditions: matched, MITRETechniques: append([]string(nil), r.MITRE...)}
		alert, err := events.NewDetectionAlert(e, result, time.Now())
		if err != nil {
			return nil, err
		}
		alerts = append(alerts, alert)
	}
	return alerts, nil
}
