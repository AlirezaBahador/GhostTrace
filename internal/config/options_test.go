package config

import (
	"path/filepath"
	"testing"
)

func TestAdditionalConfigOptions(t *testing.T) {
	p := tempConfig(t, "bpf_object: ./probe.o\nrules_path: ./rules\ninclude_comm: sh, bash\n")
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RulesPath != filepath.Join(filepath.Dir(p), "rules") || len(cfg.IncludeComm) != 2 || cfg.IncludeComm[1] != "bash" {
		t.Fatalf("bad config %+v", cfg)
	}
	for _, bad := range []string{"", "sh, sh", "foo bar", "..//", "sh,", "a*"} {
		if _, err := Load(tempConfig(t, "bpf_object: file.o\ninclude_comm: "+bad+"\n")); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestUIDAndEventTypeFilters(t *testing.T) {
	p := tempConfig(t, "bpf_object: ./probe.o\ninclude_uid: 0, 33, 65535\ninclude_event_type: process_exec, process_exit\n")
	got, err := Load(p)
	if err != nil || len(got.IncludeUID) != 3 || got.IncludeUID[0] != 0 || got.IncludeUID[1] != 33 || len(got.IncludeEventType) != 2 {
		t.Fatalf("unexpected %+v %v", got, err)
	}
	for _, s := range []string{"", "-1", "01", "4294967296", "0,0", "1,abc"} {
		if _, err := Load(tempConfig(t, "bpf_object: ./probe.o\ninclude_uid: "+s+"\n")); err == nil {
			t.Fatalf("accepted uid %q", s)
		}
	}
	for _, s := range []string{"", "network", "process_exec,process_exec", "process_exec,unknown"} {
		if _, err := Load(tempConfig(t, "bpf_object: ./probe.o\ninclude_event_type: "+s+"\n")); err == nil {
			t.Fatalf("accepted type %q", s)
		}
	}
}
