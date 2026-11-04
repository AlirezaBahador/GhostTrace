package eventio

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/AlirezaBahador/GhostTrace/pkg/events"
	"strings"
	"testing"
	"time"
)

func validJSON(t *testing.T) string {
	t.Helper()
	e := events.Event{SchemaVersion: events.SchemaVersion, EventID: "id", EventType: events.ProcessExec, Timestamp: time.Now(), TimestampSource: "userspace_receive", Source: "ebpf", Host: events.Host{Hostname: "h", BootID: "b"}, Process: events.Process{PID: 1, TID: 1, Comm: "sh"}}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
func TestVisit(t *testing.T) {
	sample := validJSON(t)
	n, err := Visit(context.Background(), strings.NewReader("\n"+sample+"\n"+sample+"\n"), func(e events.Event) (bool, error) { return true, nil })
	if err != nil || n != 2 {
		t.Fatalf("visited %d, %v", n, err)
	}
	n, err = Visit(context.Background(), strings.NewReader(sample+"\nnot valid\n"), func(e events.Event) (bool, error) { return false, nil })
	if err != nil || n != 1 {
		t.Fatalf("early stop %d, %v", n, err)
	}
	for _, input := range []string{"{\"schema_version\":\"1.0\",\"unexpected\":1}", "{}{}", "{}", strings.Repeat("x", MaxLine+4)} {
		if _, err := Visit(context.Background(), strings.NewReader(input), func(events.Event) (bool, error) { return true, nil }); err == nil {
			t.Fatalf("accepted invalid input %.50q", input)
		}
	}
	_, err = Visit(context.Background(), strings.NewReader(sample), func(events.Event) (bool, error) { return true, errors.New("test error") })
	if err == nil || !strings.Contains(err.Error(), "line 1") {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Visit(ctx, strings.NewReader(sample), func(events.Event) (bool, error) { return true, nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
