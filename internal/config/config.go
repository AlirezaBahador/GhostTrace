// Package config parses the deliberately restricted flat YAML config format
// accepted by GhostTrace v0.1. Nested YAML/aliases are NOT supported.
package config

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const MaxConfigSize = 64 * 1024

type Config struct {
	BPFObject         string
	LogLevel          string
	RulesPath         string
	IncludeComm       []string
	IncludeUID        []uint32
	IncludeEventType  []string
	EnrichProcfs      bool
	IncludeExecutable bool
}

func Load(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxConfigSize+1))
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	if len(b) > MaxConfigSize {
		return Config{}, fmt.Errorf("config exceeds %d bytes", MaxConfigSize)
	}
	cfg := Config{LogLevel: "info", EnrichProcfs: true}
	seen := map[string]bool{}
	scanner := bufio.NewScanner(strings.NewReader(string(b)))
	scanner.Buffer(make([]byte, 4096), MaxConfigSize+1)
	for lineNum := 1; scanner.Scan(); lineNum++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || line == "---" {
			continue
		}
		if strings.HasPrefix(scanner.Text(), " ") || strings.HasPrefix(scanner.Text(), "\t") {
			return Config{}, fmt.Errorf("config line %d: nested YAML is not supported", lineNum)
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			return Config{}, fmt.Errorf("config line %d: expected key: value", lineNum)
		}
		key, val := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		if seen[key] {
			return Config{}, fmt.Errorf("config line %d: duplicate key %q", lineNum, key)
		}
		seen[key] = true
		if strings.HasPrefix(val, "\"") {
			parsed, e := strconv.Unquote(val)
			if e != nil {
				return Config{}, fmt.Errorf("config line %d: invalid quoted value: %w", lineNum, e)
			}
			val = parsed
		} else if strings.HasPrefix(val, "'") {
			if !strings.HasSuffix(val, "'") || len(val) < 2 {
				return Config{}, fmt.Errorf("config line %d: unterminated single-quoted value", lineNum)
			}
			val = strings.ReplaceAll(val[1:len(val)-1], "''", "'")
		} else if strings.ContainsAny(val, "#\t{}[]") {
			return Config{}, fmt.Errorf("config line %d: unsupported YAML scalar", lineNum)
		}
		switch key {
		case "bpf_object":
			cfg.BPFObject = val
		case "log_level":
			cfg.LogLevel = val
		case "rules_path":
			cfg.RulesPath = val
		case "enrich_procfs":
			if val != "true" && val != "false" {
				return Config{}, fmt.Errorf("config line %d: enrich_procfs must be true or false", lineNum)
			}
			cfg.EnrichProcfs = val == "true"
		case "include_executable":
			if val != "true" && val != "false" {
				return Config{}, fmt.Errorf("config line %d: include_executable must be true or false", lineNum)
			}
			cfg.IncludeExecutable = val == "true"
		case "include_uid":
			if val == "" {
				return Config{}, fmt.Errorf("config line %d: empty include_uid", lineNum)
			}
			seenUIDs := map[uint32]bool{}
			for _, raw := range strings.Split(val, ",") {
				raw = strings.TrimSpace(raw)
				if raw == "" || (len(raw) > 1 && raw[0] == '0') {
					return Config{}, fmt.Errorf("config line %d: invalid uid %q", lineNum, raw)
				}
				num, err := strconv.ParseUint(raw, 10, 32)
				if err != nil || seenUIDs[uint32(num)] {
					return Config{}, fmt.Errorf("config line %d: invalid or duplicate uid %q", lineNum, raw)
				}
				seenUIDs[uint32(num)] = true
				cfg.IncludeUID = append(cfg.IncludeUID, uint32(num))
				if len(cfg.IncludeUID) > 64 {
					return Config{}, fmt.Errorf("config line %d: too many UIDs", lineNum)
				}
			}
		case "include_event_type":
			if val == "" {
				return Config{}, fmt.Errorf("config line %d: empty include_event_type", lineNum)
			}
			seenTypes := map[string]bool{}
			for _, eventType := range strings.Split(val, ",") {
				eventType = strings.TrimSpace(eventType)
				if (eventType != "process_exec" && eventType != "process_exit") || seenTypes[eventType] {
					return Config{}, fmt.Errorf("config line %d: invalid or duplicate event type %q", lineNum, eventType)
				}
				seenTypes[eventType] = true
				cfg.IncludeEventType = append(cfg.IncludeEventType, eventType)
			}
		case "include_comm":
			if val == "" {
				return Config{}, fmt.Errorf("config line %d: empty include_comm", lineNum)
			}
			seenNames := map[string]bool{}
			for _, name := range strings.Split(val, ",") {
				name = strings.TrimSpace(name)
				if len(name) == 0 || len(name) > 64 || strings.ContainsAny(name, " /\\*?!") || seenNames[name] {
					return Config{}, fmt.Errorf("config line %d: invalid or duplicate process name %q", lineNum, name)
				}
				seenNames[name] = true
				cfg.IncludeComm = append(cfg.IncludeComm, name)
			}
			if len(cfg.IncludeComm) > 64 {
				return Config{}, fmt.Errorf("config line %d: include_comm exceeds 64 entries", lineNum)
			}
		default:
			return Config{}, fmt.Errorf("config line %d: unknown key %q", lineNum, key)
		}
	}
	if err := scanner.Err(); err != nil {
		return Config{}, fmt.Errorf("scan config: %w", err)
	}
	if cfg.IncludeExecutable && !cfg.EnrichProcfs {
		return Config{}, fmt.Errorf("config: include_executable requires enrich_procfs")
	}
	if cfg.BPFObject == "" {
		return Config{}, fmt.Errorf("config: bpf_object is required")
	}
	if cfg.LogLevel != "debug" && cfg.LogLevel != "info" && cfg.LogLevel != "warn" && cfg.LogLevel != "error" {
		return Config{}, fmt.Errorf("config: invalid log_level %q", cfg.LogLevel)
	}
	if !filepath.IsAbs(cfg.BPFObject) {
		cfg.BPFObject = filepath.Join(filepath.Dir(path), cfg.BPFObject)
	}
	if cfg.RulesPath != "" && !filepath.IsAbs(cfg.RulesPath) {
		cfg.RulesPath = filepath.Join(filepath.Dir(path), cfg.RulesPath)
	}
	return cfg, nil
}
