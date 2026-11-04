package process

import (
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/AlirezaBahador/GhostTrace/pkg/events"
)

func sampleStat(pid int, name string, ppid int, start uint64) string {
	// fields 3..22; starttime is index 19 in this slice.
	fields := make([]string, 20)
	for i := range fields {
		fields[i] = "0"
	}
	fields[0] = "S"
	fields[1] = strconv.Itoa(ppid)
	fields[19] = strconv.FormatUint(start, 10)
	return strconv.Itoa(pid) + " (" + name + ") " + strings.Join(fields, " ")
}

func TestParseStat(t *testing.T) {
	s, err := ParseStat([]byte(sampleStat(999, "a) name (z", 55, 78901)))
	if err != nil {
		t.Fatal(err)
	}
	if s.PID != 999 || s.PPID != 55 || s.Comm != "a) name (z" || s.StartTimeTicks != 78901 {
		t.Fatalf("unexpected %+v", s)
	}
	for _, input := range []string{"", "123 bad", sampleStat(12, "a", 1, 0), "1 (x) S 1", sampleStat(1, "a", 1, 4) + ")"} {
		if _, err := ParseStat([]byte(input)); err == nil {
			t.Errorf("accepted malformed %q", input)
		}
	}
}

func TestReadOwnProcStat(t *testing.T) {
	s, err := ReadSnapshot(uint32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	if s.PID != uint32(os.Getpid()) || s.StartTimeTicks == 0 {
		t.Fatalf("unexpected %+v", s)
	}
}

func execEvent(pid uint32, comm string) events.Event {
	return events.Event{EventType: events.ProcessExec, Process: events.Process{PID: pid, Comm: comm}, Host: events.Host{BootID: "boot"}}
}

func TestTrackerEnrichAndPIDReuse(t *testing.T) {
	states := map[uint32]Snapshot{
		100: {PID: 100, PPID: 10, Comm: "sh", StartTimeTicks: 500},
		10:  {PID: 10, PPID: 1, Comm: "nginx", StartTimeTicks: 100},
	}
	tr := New(2).WithExecutable(true)
	tr.read = func(pid uint32) (Snapshot, error) {
		s, ok := states[pid]
		if !ok {
			return Snapshot{}, os.ErrNotExist
		}
		return s, nil
	}
	tr.exe = func(uint32) (string, error) { return "/usr/bin/dash", nil }
	e := execEvent(100, "sh")
	tr.Enrich(&e)
	if e.Process.Identity != "boot:100:500" || e.Process.PPID == nil || *e.Process.PPID != 10 ||
		e.Process.Parent == nil || e.Process.Parent.Comm != "nginx" || e.Process.Parent.Identity != "boot:10:100" {
		t.Fatalf("missing reliable-enough enrichment: %+v", e.Process)
	}
	if e.Process.Executable != "/usr/bin/dash" || tr.Len() != 1 {
		t.Fatalf("unexpected %+v", e.Process)
	}
	old := e.Process.Identity
	exit := execEvent(100, "sh")
	exit.EventType = events.ProcessExit
	tr.Enrich(&exit)
	if exit.Process.Identity != old || exit.Process.IdentitySource != "cached_exec_unverified" || tr.Len() != 0 {
		t.Fatalf("cached exit %+v", exit.Process)
	}
	states[100] = Snapshot{PID: 100, PPID: 10, Comm: "sh", StartTimeTicks: 600}
	fresh := execEvent(100, "sh")
	tr.Enrich(&fresh)
	if fresh.Process.Identity == old || fresh.Process.Identity != "boot:100:600" {
		t.Fatalf("PID reuse not handled %+v", fresh.Process)
	}
	states[100] = Snapshot{PID: 100, PPID: 10, Comm: "changed", StartTimeTicks: 700}
	wrong := execEvent(100, "sh")
	tr.Enrich(&wrong)
	if wrong.Process.Identity != "" || tr.Len() != 0 {
		t.Fatal("stale PID cache survived failed exec")
	}
}

func TestTrackerBoundsAndRace(t *testing.T) {
	tr := New(1)
	readCount := 0
	tr.read = func(pid uint32) (Snapshot, error) {
		readCount++
		if pid == 7 && readCount == 2 {
			return Snapshot{PID: 7, Comm: "sh", StartTimeTicks: 20}, nil
		}
		return Snapshot{PID: pid, Comm: "sh", StartTimeTicks: 10}, nil
	}
	tr.exe = func(uint32) (string, error) { return "", os.ErrNotExist }
	e := execEvent(7, "sh")
	tr.Enrich(&e)
	if e.Process.Identity != "" {
		t.Fatal("should reject starttime change while sampling")
	}
	tr.read = func(pid uint32) (Snapshot, error) { return Snapshot{PID: pid, Comm: "sh", StartTimeTicks: 10}, nil }
	for _, pid := range []uint32{7, 8, 9} {
		e := execEvent(pid, "sh")
		tr.Enrich(&e)
	}
	if tr.Len() != 1 {
		t.Fatalf("unbounded registry: %d", tr.Len())
	}
	exit := execEvent(7, "sh")
	exit.EventType = events.ProcessExit
	tr.Enrich(&exit)
	if exit.Process.Identity != "" {
		t.Fatal("evicted entry must not enrich exit")
	}
}

func TestTrackerOmitsUnverifiedParent(t *testing.T) {
	tr := New(5)
	tr.read = func(pid uint32) (Snapshot, error) {
		if pid == 1 {
			return Snapshot{PID: 1, PPID: 2, Comm: "sh", StartTimeTicks: 10}, nil
		}
		return Snapshot{PID: 2, Comm: "nginx", StartTimeTicks: 20}, nil // newer than child
	}
	tr.exe = func(uint32) (string, error) { return "", os.ErrNotExist }
	e := execEvent(1, "sh")
	tr.Enrich(&e)
	if e.Process.Parent != nil || e.Process.Identity == "" {
		t.Fatalf("parent should be missing %+v", e.Process)
	}
}
