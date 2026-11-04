package process

import (
	"container/list"
	"fmt"

	"github.com/ghosttrace/ghosttrace/pkg/events"
)

// Tracker is owned by one event reader and has bounded O(maxEntries) memory.
// Its FIFO-by-latest-exec eviction uses container/list for O(1) removal.
// Only procfs-verified executions get identities. Cached exit provenance
// remains explicitly unverified in case a kernel record was lost.
type Tracker struct {
	max               int
	captureExecutable bool
	data              map[uint32]*list.Element
	order             *list.List
	read              func(uint32) (Snapshot, error)
	exe               func(uint32) (string, error)
}

type entry struct {
	pid     uint32
	process events.Process
}

func New(maxEntries int) *Tracker {
	if maxEntries < 1 {
		maxEntries = 4096
	}
	return &Tracker{max: maxEntries, data: make(map[uint32]*list.Element), order: list.New(),
		read: ReadSnapshot, exe: ReadExecutable}
}

// WithExecutable opts in to potentially sensitive /proc/<pid>/exe path capture.
func (t *Tracker) WithExecutable(enabled bool) *Tracker { t.captureExecutable = enabled; return t }

func (t *Tracker) Len() int { return len(t.data) }

func (t *Tracker) remove(pid uint32) (events.Process, bool) {
	node, ok := t.data[pid]
	if !ok {
		return events.Process{}, false
	}
	delete(t.data, pid)
	t.order.Remove(node)
	return node.Value.(entry).process, true
}

func (t *Tracker) save(pid uint32, p events.Process) {
	t.remove(pid)
	t.data[pid] = t.order.PushBack(entry{pid: pid, process: p})
	if len(t.data) > t.max {
		node := t.order.Front()
		if node != nil {
			oldest := node.Value.(entry)
			delete(t.data, oldest.pid)
			t.order.Remove(node)
		}
	}
}

func (t *Tracker) Enrich(e *events.Event) {
	if e == nil {
		return
	}
	pid := e.Process.PID
	switch e.EventType {
	case events.ProcessExec:
		// PID may have been reused: never carry metadata from a prior exec.
		t.remove(pid)
		first, err := t.read(pid)
		if err != nil || first.PID != pid || first.StartTimeTicks == 0 || first.Comm != e.Process.Comm {
			return
		}
		var parent *events.Parent
		if first.PPID != 0 && first.PPID != pid {
			if p, err := t.read(first.PPID); err == nil && p.PID == first.PPID && p.StartTimeTicks <= first.StartTimeTicks && p.StartTimeTicks > 0 {
				parent = &events.Parent{PID: p.PID, Comm: p.Comm, StartTimeTicks: p.StartTimeTicks,
					Identity: identity(e.Host.BootID, p.PID, p.StartTimeTicks)}
			}
		}
		var path string
		if t.captureExecutable {
			path, _ = t.exe(pid)
		} // ESRCH/permissions are expected.
		// Detect a PID reuse, exec replacement or reparenting during our reads.
		second, err := t.read(pid)
		if err != nil || second.PID != first.PID || second.PPID != first.PPID || second.StartTimeTicks != first.StartTimeTicks || second.Comm != first.Comm {
			return
		}
		// Recheck parent's identity: a reused PID must not cause a confident claim.
		if parent != nil {
			confirm, err := t.read(parent.PID)
			if err != nil || confirm.StartTimeTicks != parent.StartTimeTicks || confirm.Comm != parent.Comm || confirm.PID != parent.PID {
				parent = nil
			}
		}
		ppid := first.PPID
		e.Process.PPID = &ppid
		e.Process.Identity = identity(e.Host.BootID, pid, first.StartTimeTicks)
		e.Process.IdentitySource = "procfs_starttime_ticks"
		e.Process.StartTimeTicks = first.StartTimeTicks
		e.Process.Executable = path
		e.Process.Parent = parent
		t.save(pid, e.Process)
	case events.ProcessExit:
		cached, ok := t.remove(pid)
		if ok && cached.Comm == e.Process.Comm {
			e.Process.Identity = cached.Identity
			e.Process.IdentitySource = "cached_exec_unverified"
			e.Process.StartTimeTicks = cached.StartTimeTicks
			e.Process.PPID = cached.PPID
			e.Process.Executable = cached.Executable
			e.Process.Parent = cached.Parent
		}
	}
}

func identity(boot string, pid uint32, ticks uint64) string {
	return fmt.Sprintf("%s:%d:%d", boot, pid, ticks)
}
