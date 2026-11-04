# GhostTrace

> **Engineering status — 2026-11-04.** GhostTrace has a real eBPF process-probe *source implementation* and tested unprivileged Go components: a JSONL analyzer, query CLI, and a bounded, read-only JSONL REST/SSE API. A React/TypeScript dashboard has source but **has not been built** because npm packages are unavailable in this environment. **Kernel BPF compilation, agent full build, and privileged integration tests remain unverified.** Network/file hooks and SQLite are not implemented. Do not represent this repository as a fully functional EDR or a released, VM-verified v0.1.0. See [release status](docs/RELEASE_STATUS.md) and [API reference](docs/API.md).

## Newly implemented: offline investigation API

```bash
# Tested offline (standard library-only Go components)
make analyze query server
./build/ghosttrace-server -events ./events.jsonl -rules ./rules
# From a second terminal: curl 'http://127.0.0.1:7766/api/v1/events?order=desc&limit=20'
```

The API requires an **existing JSONL file**, which may be produced by running the kernel agent in a capable Linux VM (not verified here). It does not create fake telemetry or start eBPF itself. It binds only to loopback, optionally checks a Bearer token from `GHOSTTRACE_API_TOKEN`, supports limited filtering/pagination, observed process graphs, rule metadata, and best-effort SSE of appended events. The optional dark React dashboard reads that API; its source lives in [`dashboard/`](dashboard/). To build the dashboard on a network-connected host: `cd dashboard && npm install && npm run build`. React dependencies and their lockfile have **not yet been resolved or tested**. Review [`docs/API.md`](docs/API.md) before exposing sensitive metadata.


**Observe Processes. Correlate Behavior. Detect Threats.**

> **Status: experimental, not a verified v0.1.0 release.** The full Linux eBPF agent has NOT been kernel-integration tested in the available environment. This is a monitoring-only project under development, not a production EDR or comprehensive threat detector.

GhostTrace is a small, auditable, standalone Linux runtime telemetry agent written in Go and C/eBPF. The initial kernel collector observes **successful process execution** and **thread-group leader exit tracepoints** using a 1 MiB BPF ring buffer and writes structured, versioned JSON Lines. Userspace extensions inspired by Tracee, Tetragon, Falco and Kunai provide best-effort process enrichment, scoped output filtering, a deliberately limited YAML rule engine, and executable offline JSONL detection and investigation/query tools. The eBPF agent remains operational by design without the optional backend or frontend.

Read [the upstream technical comparison](docs/UPSTREAM_RESEARCH.md) for exactly what was learned, integrated, deferred, and excluded; no upstream source code was copied. Read [detection semantics](docs/DETECTION.md) and [verification](docs/VERIFICATION.md) before treating alerts as evidence.

## Current feature status

| Feature | Status | Critical qualification |
| --- | --- | --- |
| eBPF `sched_process_exec` / `sched_process_exit` | **Implemented source; kernel test NOT RUN** | Neither failed exec attempts nor all thread-group exits are guaranteed |
| Go loader, strict 48-byte event decoder, JSONL output | **Implemented source; full agent build BLOCKED** | `cilium/ebpf` is not available in this container |
| Graceful shutdown and BPF ring buffer reserve-failure counter | **Unit tested / source implemented** | Drops other than ringbuf reservations are not measured |
| Versioned event envelope, host boot ID, UTC receive-time | **Unit tested** | `kernel_monotonic_ns` is not an epoch timestamp |
| Linux `/proc` starttime-based process ID and observed parent | **Experimental; unit tested** | Subject to PID reuse / exit / reparenting races; not authoritative ancestry |
| Bounded, PID-replacing process cache | **Unit tested** | 4096 entries in live agent; cached exits marked unverified |
| Optional executable-path enrichment | **Unit tested** | Off by default to avoid collecting unneeded sensitive paths |
| Strict YAML detection rules, evidence-linked JSON alerts | **Unit tested** | Exact process/parent-name rules only; rule path is opt-in |
| Process name, UID and event-type output filters | **Unit tested** | Filters raw JSONL **after detection**, not in-kernel collection or alerts |
| `ghosttrace-query` offline investigation CLI | **Built and unit tested** | Exact `comm`, UID, event type, identity, rule, severity and receive/generation time filters; no database |
| `ghosttrace-analyze` offline JSONL rule evaluation | **Built and unit tested** | Consumes actual input provided by operator; no fabricated live telemetry |
| Network / file eBPF probes, complete ancestry | **Planned** | No claims of network/file visibility |
| Read-only JSONL REST API + best-effort SSE stream | **Built and unit/race tested** | Loopback-only file-backed API; not SQLite, not WebSocket |
| React/TypeScript dark dashboard | **Source implemented; npm build NOT RUN** | No fake telemetry; requires npm dependencies and browser verification |
| SQLite persistence/migrations, WebSocket | **Planned** | JSONL is not indexed or durable transaction storage |
| Privileged integration and performance measurements | **NOT RUN** | Requires a suitable Linux VM |

## Architecture

```text
Linux kernel >= 5.8 (feature baseline, not a compatibility guarantee)
 sched_process_exec ──┐
                      ├─ eBPF C ── 1 MiB ring buffer ── Go collector
 sched_process_exit ──┘      │                              │
                failed ringbuf reservations counter    48-byte decoder
                                                         │
                                           schema + UTC receive time
                                                         │
                                   optional bounded procfs enrichment
                                                         │
                                      optional YAML rule evaluation
                                         │               │
                               detection alerts      output filter
                                         │               │
                                         └───── JSONL ────┘
                                             (stdout)

   separate unprivileged tools:
     `ghosttrace-analyze`: JSONL -> validated rules -> alerts
     `ghosttrace-query`: JSONL -> validated exact-match filters -> JSONL
   diagnostics and final loss counter -> stderr
```

## Linux requirements

- Linux **5.8+** kernel with supported eBPF ring buffer, tracepoints and policies; `amd64`/`arm64`, little-endian.
- Go **1.23.2+**, Clang/LLVM **with BPF target support**, `make`, `gcc`, Linux UAPI headers, initial network access to download `github.com/cilium/ebpf`.
- Runtime capabilities for loading/attaching eBPF: typically `CAP_BPF` plus `CAP_PERFMON` or legacy `CAP_SYS_ADMIN`, depending on kernel, capabilities and LSM policy. Root without those capabilities may not work. Run on a trusted Linux VM or host, not a privileged container.
- Existing fixed-offset tracepoints do **not** require vmlinux BTF. CO-RE may require it in future.

On Debian/Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y clang llvm make gcc linux-libc-dev golang-go
clang -target bpf -c -x c /dev/null -o /tmp/gt-bpf-check.o  # verify BPF backend
```

## Build and run

```bash
# From the project root; on first network-connected build:
go mod tidy                  # then commit generated go.sum to the repository
make build CLANG=/usr/bin/clang

# Validate config and rules without BPF privileges:
./build/ghosttrace-agent -config config.yaml -validate

# In a trusted Linux VM with necessary eBPF capabilities:
umask 077
sudo ./build/ghosttrace-agent -config config.yaml > events.jsonl 2> agent.log
```

Generate a real event in a separate terminal:

```bash
/bin/sleep 1
```

Shut down the agent with Ctrl+C; inspect `events.jsonl` and `agent.log`. The BPF file is loaded from the configured path (`build/process.bpf.o`); no synthetic telemetry is silently substituted when BPF is unavailable. Stdout blocking can cause kernel ring-buffer pressure and dropped events. Loss accounting currently covers only **failed ring-buffer reservations**, not all possible losses.

### Configuration

The config loader accepts a restricted **flat YAML subset**, not arbitrary YAML. Unknown or duplicate fields, invalid values and files over 64 KiB fail closed. Relative file paths resolve relative to the config file.

```yaml
bpf_object: ./build/process.bpf.o
log_level: info
enrich_procfs: true
include_executable: false
# rules_path: ./rules              # opt in to YAML detection
# include_comm: nginx, sh, bash    # optional raw JSONL filter
# include_uid: 0, 33              # optional exact UIDs on raw records
# include_event_type: process_exec # optional raw event-type filter
```

`enrich_procfs` enables best-effort `/proc` identity and current-parent sampling. `include_executable` additionally captures the potentially sensitive executable symlink path (default **false**). `rules_path` is an optional rule file or directory; it is validated before loading the BPF object. Parent-matching rules need `enrich_procfs: true` (the agent rejects that mismatch during startup). All alerts go to stdout as JSONL even if their triggering process event is excluded by any output filter (`include_comm`, `include_uid`, `include_event_type`). These filters do not reduce BPF overhead, prevent collection, or guarantee privacy for fields that may still be present in alerts.

Sample detection: [`rules/GT-001.yaml`](rules/GT-001.yaml), which matches a shell with a currently observed `nginx`/`apache2` parent. It is not enabled until `rules_path` is configured. Every rule evaluation is based on actual monitored or supplied events, never built-in synthetic incidents. See [the exact, deliberately limited rule grammar](docs/DETECTION.md).

### Offline detection and investigation (do not require eBPF)

```bash
make analyze query
./build/ghosttrace-analyze -rules ./rules -input ./events.jsonl > alerts.jsonl
./build/ghosttrace-query -input ./events.jsonl -comm sh,bash -uid 33 -type process_exec > shells.jsonl
./build/ghosttrace-query -input ./alerts.jsonl -type detection_alert -severity high,critical > important-alerts.jsonl
./build/ghosttrace-query -input ./events.jsonl -since 2026-11-04T00:00:00Z -limit 100 > first-hundred.jsonl
```

Input must be versioned GhostTrace JSONL; both tools reject malformed or unknown fields, and support records up to 1 MiB. `ghosttrace-query` streams valid, matching events in **input order**; it neither reconstructs a tree nor guarantees chronological order. Its `-since`/`-until` compare **userspace receipt or detection-generation time**, not exact kernel event time. `-limit` ends scanning early: unscanned lines are not validated. No data is produced without actual operator-supplied input. Both tools were actually compiled and unit tested in the constrained environment. The same validated rule engine runs in the live agent and offline analysis.

## Event example (**illustrative schema only; not a captured record**)

```json
{"schema_version":"1.0","event_id":"9bd9c843-7b9e-4a2b-9ca4-91f278c4ed1c","event_type":"process_exec","timestamp":"2026-11-04T12:30:00Z","timestamp_source":"userspace_receive","kernel_monotonic_ns":123456789,"host":{"hostname":"illustrative-host","boot_id":"illustrative-boot-id"},"process":{"pid":4821,"tid":4821,"uid":1000,"gid":1000,"comm":"sh","identity":"illustrative-boot-id:4821:98765","identity_source":"procfs_starttime_ticks","start_time_ticks":98765,"ppid":1024,"parent":{"pid":1024,"comm":"nginx","identity":"illustrative-boot-id:1024:1234","start_time_ticks":1234}},"source":"ebpf"}
```

Kernel fields: `pid`, `tid`, `uid`, `gid`, `comm`, `event_type`, `kernel_monotonic_ns`. Userspace fields: host boot ID/hostname, UUID, UTC **receipt** time and, only when the process still exists and procfs reads are consistent, current parent and start-time ticks. Executable path is collected only when enabled. A Linux `/proc` parent may **not** be the parent at kernel hook time. An exit may reuse cached identity with source `cached_exec_unverified`. Alert records are `detection_alert` from source `detection` with `timestamp_source: detection_generated` and structured evidence IDs.

## Tests and validation

```bash
# Userspace-only checks; no cilium/ebpf dependency downloads required:
make test-userspace
make analyze query

# Full checks on a host that can download Go dependencies and build eBPF:
go test -race ./...
go vet ./...
make build CLANG=/usr/bin/clang

# Real kernel integration tests, on an isolated privileged Linux VM:
sudo bash tests/integration/process.sh
sudo bash tests/integration/detection.sh
```

GitHub Actions build userspace and (on a capable runner) BPF/agent components; privileged kernel test runs require separate isolation and granted capabilities. **Full kernel verification and performance numbers have NOT been produced in this environment.** See [VERIFICATION.md](docs/VERIFICATION.md), [PERFORMANCE.md](docs/PERFORMANCE.md), [SECURITY.md](docs/SECURITY.md), and [THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Security and limits

No blocking, firewall changes, credential collection, file-content capture, remote API, or privileged Docker execution. The agent's eBPF object and rule files must be administrator-controlled; stdout should be redirected to permission-restricted files (`umask 077`). Process metadata and optionally executable paths can be sensitive. Alerts indicate a **rule match**, not proof of compromise. No guarantees of complete coverage, global event ordering, exactly-once delivery, zero event loss, or accurate ancestry for short-lived processes.

**Not implemented:** fork/process creation hook, kernel-authenticated process birth times, network connect attempts/outcomes, file operations, containers, reliable event replay, multi-event attack-chain correlation, SQLite database, WebSocket, persistent alert management, external exporters or benchmarked kernel/agent CPU overhead. **Implemented separately:** a local read-only JSONL API with optional Bearer auth and best-effort SSE; **unverified source:** a React dashboard (npm build pending).

## Roadmap (gated)

1. **Phase 1 release gate:** fetch Go modules, build full agent with BPF-capable Clang, and verify real exec/exit hook instrumentation on a privileged Linux VM. Not yet done.
2. **Phase 2:** kernel-derived parent/fork identity and edge-case tests, real network attempt telemetry, safe file semantics, verified correlation and expanded rule grammar. Experimental procfs/rules functionality already exists but is not a substitute for these checks.
3. **Phase 3:** durable SQLite with retention and a localhost-authenticated API/stream, metrics and exporters.
4. **Phase 4:** React/TypeScript investigative dashboard on actual data.
5. **Phase 5:** privileged CI, independent security review, loss/performance benchmarks, systemd and release packaging.

## Contributing and license

Submit small changes with unit tests, explicit event semantics and updated documentation. Follow [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md). Do not include confidential host events in issues. Original GhostTrace code is Apache License 2.0 ([LICENSE](LICENSE)). No code was transplanted from the upstream research projects; Kunai is GPL-3.0 and must not be copied under the project's license without a deliberate legal compatibility review.