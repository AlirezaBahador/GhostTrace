# GhostTrace development changelog

## Unreleased — research and hardening (2026-11-04)

This is NOT a production or kernel-verified release.

- Reviewed architecture-critical public source/documentation for Tracee, Tetragon, Falco and Kunai; recorded explicit licensing and feature gaps in `docs/UPSTREAM_RESEARCH.md`.
- Added experimental, bounded procfs process identity/parent enrichment and opt-in single-event YAML detection and offline `ghosttrace-analyze`.
- Added streaming, validated `ghosttrace-query` CLI with exact process, UID, event type, identity, rule, severity and time filters.
- Added live-agent post-detection output selectors for process `comm`, UID and event type, never suppressing detection alerts.
- Centralized size-limited JSONL decoding and added unit/race tests.
- The full eBPF agent still cannot be compiled/loaded in this environment: BPF-enabled Clang, downloaded `cilium/ebpf`, and runtime kernel privileges are unavailable. Kernel integration is **NOT RUN**, not passed.

## Phase 1 baseline candidate

- Linux eBPF exec/leader-exit tracepoint source, ring buffer and failed reservation counter.
- Go loader/decoder, JSON Lines exporter, signal-aware shutdown, initial unit and isolated VM integration scripts.
- Full kernel execution and verifier acceptance remain unverified.

## Development update — 2026-11-04 (not a tagged release)

- Added `ghosttrace-server`: real loopback-only, read-only JSONL REST endpoints with filtering, bounded pagination, exact detail lookup, alert lookup, observed process graphs, rule metadata and file-only metrics.
- Added opt-in Bearer auth from environment, HTTP Host restriction, bounded concurrent request handling and file size/record size limits.
- Added best-effort appended-file SSE stream, including rotation/truncation detection and no-replay limitations.
- Added experimental React/TypeScript dashboard source with real API-only data paths and a React Flow process-relationship graph. npm build has not run due to offline dependencies.
- Added repeatable unprivileged HTTP smoke test, userspace microbenchmarks, example systemd/logrotate templates, API and release-gate docs.
- **Outstanding:** BPF compiler/agent build and privileged kernel integration tests; no network/file telemetry, SQLite, WebSocket or durable stream guarantees.