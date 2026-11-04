package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tempConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoad(t *testing.T) {
	path := tempConfig(t, "# comment\nbpf_object: './build/process.bpf.o'\nlog_level: debug\n")
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.LogLevel != "debug" || got.BPFObject != filepath.Join(filepath.Dir(path), "build/process.bpf.o") {
		t.Fatalf("config: %+v", got)
	}
	path = tempConfig(t, "bpf_object: /tmp/test.o\n")
	got, err = Load(path)
	if err != nil || got.LogLevel != "info" || got.BPFObject != "/tmp/test.o" {
		t.Fatalf("defaults: %+v %v", got, err)
	}
}

func TestLoadRejectsInvalid(t *testing.T) {
	tests := []struct{ name, content string }{
		{"missing object", "log_level: info\n"},
		{"unknown", "bpf_object: file.o\nsecret: true\n"},
		{"duplicate", "bpf_object: file.o\nbpf_object: other.o\n"},
		{"nested", "bpf_object: file.o\n  key: value\n"},
		{"wrong level", "bpf_object: file.o\nlog_level: trace\n"},
		{"bad YAML", "bpf_object file.o\n"},
		{"unsafe scalar", "bpf_object: file.o #comment\n"},
		{"unclosed quoted", "bpf_object: \"bad\n"},
		{"oversized", "bpf_object: " + strings.Repeat("x", MaxConfigSize) + "\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Load(tempConfig(t, tt.content)); err == nil {
				t.Fatal("expected load error")
			}
		})
	}
}
