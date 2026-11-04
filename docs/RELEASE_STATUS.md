> **Audit update (2026-11-04):** The working audit branch addresses module naming, generates lockfiles through a connected GitHub runner and requires explicit API auth. A dependency vulnerability in cilium/ebpf v0.17.3 required upgrading to v0.22.0 (Go >= 1.25), pending a clean CI run. See [audit](AUDIT_2026-11-04.md). This report contains historical entries and the project is still NOT READY to release.

# Release gates and implementation status (2026-11-04)

GhostTrace is **not a completed production-grade endpoint detection and response product**. The repository is an incremental engineering project. Do not tag or market it as a verified `v0.1.0` until all Phase-1 gates pass.

| Capability | Status | Evidence / caveat |
| --- | --- | --- |
| Process exec + thread-group leader exit tracepoint programs | **Source implemented; kernel unverified** | `ebpf/process.bpf.c`; BPF target compiler, `cilium/ebpf` dependency and kernel permissions unavailable here. |
| BPF ring reader / Go loader / JSONL agent | **Source implemented; full binary unverified** | `cmd/agent`, `internal/collector`, decoder, exporter. |
| Decode, versioned JSON schema, offline JSONL validation | **Userspace unit-tested** | `go test ./internal/decoder ./pkg/events ./internal/eventio`. |
| Procfs process identity, parent enrichment and bounded cache | **Userspace unit-tested, best effort** | Parent at userspace read time, not kernel event-time certainty. |
| YAML rules + process/parent matching + alert evidence | **Userspace unit-tested** | No multi-event/time-window logic. |
| Offline analyze and query CLIs | **Compiled and unit-tested in this environment** | Real JSONL inputs; no kernel simulation in production. |
| Local read-only JSONL API | **Compiled, unit/race tested and HTTP smoke tested** | JSONL scan, filtering, pages, alerts, observed process graph, auth, SSE. No SQLite. |
| React TypeScript Vite dashboard source | **Experimental, build not run** | npm dependencies unavailable; direct runtime verification blocked. No hardcoded metric values. |
| Outbound TCP telemetry | **Not implemented** | Attempt and success must remain different events when added. |
| Selected file telemetry | **Not implemented** | No file-content collection, no coverage claim. |
| SQLite persistent store, migrations / retention | **Not implemented** | JSONL is an append-only operator-maintained file. |
| True agent health / performance metrics | **Not implemented** | BPF ring reserve failures can be logged on agent shutdown only if actually loaded. |
| Kernel integration exec/exit/detection tests | **NOT RUN** | Requires an isolated privileged Linux VM and BPF-capable toolchain. |
| Agent threat response/blocking/enforcement | **Out of scope** | Monitoring-only design. |

## Verified locally in this revision

Host: Debian 13, Linux 6.18.57, Go 1.23.2, Swift Clang 17. No eBPF kernel permissions or `/sys/kernel/btf/vmlinux`; Clang BPF target absent; Go dependency and npm registry DNS unavailable. The standard-library-only Go subset is independently verifiable.

```bash
GOPROXY=off go test -race ./cmd/analyze ./cmd/query ./cmd/server ./internal/api ./internal/eventio ./internal/filter ./internal/agent ./internal/config ./internal/decoder ./internal/detection ./internal/exporter ./internal/process ./pkg/events
GOPROXY=off go vet ./cmd/analyze ./cmd/query ./cmd/server ./internal/api ./internal/eventio ./internal/filter ./internal/agent ./internal/config ./internal/decoder ./internal/detection ./internal/exporter ./internal/process ./pkg/events
make server analyze query
```

The first two commands **PASS**, and the last command compiles the three unprivileged Go CLIs. Tests use constructed events only as labeled fixtures. `go test ./...` and `make build` cannot pass here because `github.com/cilium/ebpf` has not been downloaded and `go.sum` is absent. `npm run build` has **NOT RUN** due to missing npm dependencies. Do not conflate C host-target syntax validation with a BPF verifier pass.

## Required next release validations

1. On a network-connected builder: `go mod tidy`, review and commit `go.sum`, `go mod verify`, `go test -race ./...`, `go vet ./...`, `make build CLANG=/usr/bin/clang` with actual BPF backend, `file build/process.bpf.o` to confirm EM_BPF.
2. In an isolated privileged Linux VM (>=5.8): run `sudo bash tests/integration/process.sh` and `sudo bash tests/integration/detection.sh`; inspect real JSONL, parent enrichment correctness, ring reserve failure counters and shutdown cleanup.
3. Resolve dashboard npm dependencies; generate and commit `package-lock.json`, run `npm ci && npm run build`, then real browser/API integration and security review (CSP, token handling, SSE reconnect).
4. Design and **verify** TCP attempt/outcome and file hook semantics, bounded kernel collectors, event-loss metrics, SQLite retention/migrations, and multi-event correlation before claiming those capabilities.
5. Benchmark CPU/RAM, BPF allocations, event loss and monitored workload slowdown on measured hardware. No invented benchmarks.
