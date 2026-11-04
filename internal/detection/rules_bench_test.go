package detection

import (
	"github.com/AlirezaBahador/GhostTrace/pkg/events"
	"testing"
	"time"
)

// This is a synthetic rule-matching microbenchmark, NOT a VM/kernel benchmark.
func BenchmarkRuleMatchNoHit(b *testing.B) {
	engine, err := New([]Rule{{ID: "GT-901", Name: "Bench", Enabled: true, Severity: "high",
		Conditions: Conditions{ChildProcess: []string{"bash"}}, Actions: []string{"alert"}}})
	if err != nil {
		b.Fatal(err)
	}
	e := events.Event{SchemaVersion: events.SchemaVersion, EventID: "fixture", EventType: events.ProcessExec,
		Timestamp: time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC), TimestampSource: "userspace_receive", Source: "ebpf",
		Host: events.Host{Hostname: "bench", BootID: "fixture"}, Process: events.Process{PID: 123, TID: 123, Comm: "safe"}}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := engine.Evaluate(e); err != nil {
			b.Fatal(err)
		}
	}
}
