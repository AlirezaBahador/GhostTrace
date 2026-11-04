\n> **2026-11-04 P0 audit verification addendum:** GitHub Actions run `41837303762` for commit `b49e70c` completed successfully in Go/Agent/BPF build, dashboard build, and vulnerability scan jobs. This is a BPF object compile and userspace test result, not a live kernel attach/integration result. See [P0 audit](AUDIT_2026-11-04.md). The historical offline test results below describe the initial build environment.\n# Verification record — GhostTrace source package

## Source and runtime inspected (2026-11-04)

Imported existing user project archive (`ghosttrace-source.zip`, 28 files) into a working directory, rather than creating a replacement mock repository. Environment: **Debian 13**, host Linux **6.18.57**, **Go 1.23.2**, `amd64`, Swift Clang **17**. This container has no `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_ADMIN` or accessible `/sys/kernel/btf/vmlinux`; the installed Clang has **no BPF target**. GitHub/Go module DNS is unavailable from the terminal. External upstream research was read via authorized public GitHub/web retrieval, not by locally cloning the whole four upstream repositories.

### Baseline audit before changes

- The existing source supplied a real BPF C tracepoint program, Go `cilium/ebpf` loader, 48-byte decoder, JSONL sink, basic flat YAML config, signal shutdown, limited ringbuf reserve-failure metric and original unit/kernel integration tests.
- Initial offline userspace test command: `GOPROXY=off go test ./internal/decoder ./internal/config ./internal/agent ./internal/exporter ./pkg/events` — **PASS** (5 packages).
- Initial host-target C syntax check — **PASS** (not BPF object compilation).
- No working agent executable or BPF ELF was present in the source archive. The prior repository had no `go.sum` and no downloaded cilium dependency in this environment.

### Changes implemented during this revision

- `internal/process`: `/proc` parser, PID/starttime/boot identity, parent observation with validation and double-checks, optional executable path, bounded 4096-entry FIFO-by-exec cache with O(1) removal/eviction. No assertions of authoritative ancestry.
- `pkg/events`: optional process and parent identity fields, separately structured `detection_alert` with matching condition strings and evidence references; separate detection generation timestamp/source.
- `internal/detection`: restricted YAML loader and validator, enabled/disabled rules, severity, MITRE metadata, process/parent name matching, exclusions and multiple validated rules.
- `internal/agent`, `cmd/agent`, `internal/config`: optional detection/enrichment, output-scoped filtering, counts, offline `-validate` mode (source implemented; full agent build unavailable).
- `cmd/analyze`: unprivileged, **buildable** JSONL-to-alert analyzer using the same rule engine as the agent; rejects invalid events and oversized input.
- `rules/GT-001.yaml`, tests, reference documentation, VM-only `tests/integration/detection.sh`, Make targets and CI analyzer build step.

### Additional implementation — streaming investigation and safer filtering

- `internal/filter`: exact-match AND policy over process command, numeric UID, event type, process identity, alert rule ID, severity and inclusive userspace timestamp bounds; supports OR within a selector list. No regex, no path-content capture, no in-kernel filtering.
- `internal/eventio`: common line-numbered, schema-validated JSONL scanner with a 1 MiB record cap and cancellation support; shared by analyzer and query tool.
- `cmd/query`: a **real, compiled, unprivileged** `ghosttrace-query` executable, streaming recorded JSONL and writing only matching validated records. Optional `-limit` is early termination; unscanned input is not validated. No fake event provider.
- Live agent config supports `include_uid` and `include_event_type` in addition to `include_comm`; the filter operates **after** rule evaluation and does **not** suppress alerts or BPF event capture.
- Added unit tests for query selection, malformed input and bounds, filter AND/OR and alert scoping, configuration fail-closed behavior, and detection-not-suppressed semantics. Added CI build and README usage.

### Executed checks AFTER these changes

| Check | Status | Notes |
| --- | --- | --- |
| `gofmt -l cmd internal pkg` | **PASS** | No unformatted Go files |
| `GOPROXY=off make test-userspace` | **PASS** | 11 packages: `cmd/analyze`, `cmd/query`, eventio, filter, agent, config, decoder, detection, exporter, process, events |
| `GOPROXY=off make test-userspace-race` | **PASS** | Go race detector, same 11 packages |
| `GOPROXY=off go vet ./cmd/analyze ./cmd/query ./internal/eventio ./internal/filter ./internal/agent ./internal/config ./internal/decoder ./internal/detection ./internal/exporter ./internal/process ./pkg/events` | **PASS** | Same 11 packages |
| `GOPROXY=off make analyze query` | **PASS** | Compiled Linux/amd64 executables: `build/ghosttrace-analyze`, `build/ghosttrace-query` |
| `./build/ghosttrace-analyze -rules rules -input /dev/null` | **PASS** | Loaded/validated rule, emitted 0 alerts on empty input (not a telemetry test) |
| `./build/ghosttrace-query -input /dev/null -comm sh -uid 1000 -type process_exec` | **PASS** | Emitted 0 events on empty input (not a telemetry test) |
| `clang -fsyntax-only -Wall -Werror -Iebpf/include -I/usr/include/x86_64-linux-gnu ebpf/process.bpf.c` | **PASS** | Host-target C syntax only |
| `bash -n tests/integration/detection.sh tests/integration/process.sh` | **PASS** | Shell syntax check only |
| `clang -target bpf -O2 -c -x c /dev/null -o /tmp/ghosttrace-bpf-test.o` | **BLOCKED** | `No available targets are compatible with triple "bpf"` |
| `GOPROXY=off go build ./cmd/agent` | **BLOCKED** | Missing `go.sum` entries and no network access to retrieve `github.com/cilium/ebpf` |
| `make build` | **BLOCKED** | The same missing BPF compiler target and Go dependencies |
| `sudo bash tests/integration/process.sh` | **NOT RUN** | Requires built agent/BPF and privileged isolated VM |
| `sudo bash tests/integration/detection.sh` | **NOT RUN** | Requires built agent/BPF and privileged isolated VM |
| End-to-end kernel event capture | **NOT RUN** | Not possible in current container |
| BPF/event-loss and CPU performance benchmarks | **NOT RUN** | No valid kernel test environment |

**Do not interpret unit tests or host C syntax as proof of BPF verifier acceptance or runtime behavior.** No benchmark data are fabricated. Tests that use constructed records use them only as explicit test fixtures, not as production telemetry.

## Release gates still unsatisfied

1. On a network-connected Linux builder, `go mod tidy` and commit the generated `go.sum`; verify `go mod verify` and the dependency vulnerability scan.
2. Install a **BPF-capable** Clang/LLVM; run `make build CLANG=/usr/bin/clang`, inspect ELF and fix any verifier/build issues.
3. On a privileged isolated Linux VM, verify actual exec + leader-exit and the parent-shell detection (`sudo bash tests/integration/process.sh` and `sudo bash tests/integration/detection.sh`). Verify telemetry loss counters and meaningful exit semantics.
4. Execute `go test -race ./...`, `go vet ./...`, evaluate security hardening and measure performance in the environment of intended use.
5. Only then consider Phase 1 done and mark a release. Until that point, **the full eBPF agent remains an unverified implementation candidate**. The offline analyzer, offline query CLI and 11-package userspace test suite are separately verified here.