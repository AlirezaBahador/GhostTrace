# Architecture — v0.1 phase 1

## Components

1. `ebpf/process.bpf.c`: two tracepoint programs. Kernel helper APIs provide IDs, monotonic clock, and 16-byte task comm; records are written to a one-megabyte ring buffer. An atomic `BPF_MAP_TYPE_ARRAY` counter counts ring-buffer reserve failures.
2. `internal/collector`: cilium/ebpf ELF collection loader, tracepoint link attachment, ringbuf reader, drop-counter readout, and explicit resource ownership. Failing to attach any required hook is fatal: the agent does not quietly switch to partial monitoring.
3. `internal/decoder`: validated fixed-width, 48-byte, little-endian wire format. The kernel does not marshal JSON.
4. `pkg/events`: public schema 1.0, host boot ID, hostname, random event UUID, receipt-time UTC timestamp. Converting monotonic kernel time directly into wall time would require an independently calibrated mapping and clock-change handling; v0.1 therefore does not make this claim.
5. `internal/agent`: synchronous event processing and context-driven stop of blocking ringbuf reads. No Go worker pool or unbounded backlog.
6. `internal/exporter`: synchronous JSONL writer, event schema validation, propagation of I/O failures.
7. `cmd/agent`: signal handling, configuration, structured diagnostics to stderr, event output on stdout.

## Wire protocol v1

| Offset | Bytes | Field | Source |
| ---: | ---: | --- | --- |
| 0 | 8 | `monotonic_ns` | `bpf_ktime_get_ns` |
| 8 | 4 | `pid` (TGID) | `bpf_get_current_pid_tgid` |
| 12 | 4 | `tid` | `bpf_get_current_pid_tgid` |
| 16 | 4 | `uid` | `bpf_get_current_uid_gid` |
| 20 | 4 | `gid` | `bpf_get_current_uid_gid` |
| 24 | 4 | `event_type` | `1` exec, `2` leader exit |
| 28 | 4 | reserved | zero |
| 32 | 16 | `comm` | `bpf_get_current_comm` |

The total record size is **48 bytes**, validated in C with `_Static_assert` and in Go with strict offset decoding. This is currently an internal wire format, not an externally supported ABI. The JSON schema is versioned separately.

## Kernel event semantics and gaps

`sched_process_exec` is observed after a successful execution path, not every attempted `execve` syscall. `sched_process_exit` fires per task: GhostTrace intentionally ignores nonleaders. A leader exit may occur while other threads remain active; `process_exit` should not be interpreted as a completed thread-group teardown. Both hooks are passive observers, not preventive controls. A dropped ring-buffer record causes a gap; the agent does not synthesize missing events.

`ppid`, executable pathname, and process start time are intentionally omitted until trustworthy capture and identity correlation are implemented. PID reuse makes naive userspace `/proc/<pid>` enrichment dangerous without identity checks.

## Backpressure and shutdown

The ring buffer holds at most 1 MiB of records. A failed reserve increments `ringbuf_drops` in a BPF array map. A slow sink blocks Go reads; the kernel may drop new events. There are no producer acknowledgements, durable queue, or exactly-once guarantees. On SIGINT/SIGTERM, the Go context stops reads, closes attached links and maps, and logs a best-effort drop-count snapshot. This deliberately prioritizes bounded resource use over draining an unbounded backlog.

## Future extensions

Stable process identity `(boot_id, tgid, start_time_ns)`, fork tracepoint, ancestry graph, network attempts, sensitive-file policies, rule engine, SQLite, API, and dashboard are **not in phase 1**. Preserve the event schema compatibility contract when these additions are implemented.