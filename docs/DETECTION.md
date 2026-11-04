# Detection and process enrichment (experimental post-Phase-1 extension)

## What is functional

- `internal/process` parses Linux `/proc/<pid>/stat` and optionally `/proc/<pid>/exe`. On a live process execution, it constructs an **observed** identity `boot_id:PID:starttime_ticks`. Reads are checked before and after enrichment to reduce (not eliminate) procfs races. The observed parent is recorded only when a currently live PID has a plausible start time. Parent information may reflect reparenting between kernel event and userspace read.
- A memory-bounded, single-reader cache retains up to **4096** most recently observed processes in the agent. New executions replace old PID entries; exits release them. Exit metadata is labeled `cached_exec_unverified`: if a process was recycled or an event was lost, the cached association might be wrong.
- Rules are loaded **before** attempting BPF attachment; a malformed rule fails configuration. Disabled rules never match. Rule matching is single-event and requires **positive evidence**; unknown parent => no alert for a rule with `parent_process`.
- All matches become `detection_alert` JSONL entries with rule ID/name/severity, triggering event IDs, process data, matched conditions and optional MITRE references. Alerts have a userspace **generation timestamp** (`timestamp_source: detection_generated`) and do not pretend to be kernel-originated events.
- The `include_comm`, `include_uid`, and `include_event_type` filters apply **only to raw kernel events after rule evaluation**: detected alerts are always output even if their trigger was filtered. This means an alert can reference a triggering event not exported. No queue is added; output remains synchronous and best-effort.

## Supported YAML subset

A rule is a **single YAML document per file**, with spaces-only indentation: root keys at zero spaces, list keys at two spaces and list items at two or four spaces. Scalar values may be bare, `'single quoted'` or `"double quoted"` (with no escapes). No inline lists/maps, merge keys, tags, aliases, anchors, expressions, multiline scalars, or multiple documents. Files are limited to 64 KiB, directories to 128 `.yml`/`.yaml` rule files. Unknown or duplicate keys are rejected. This is **not** the full YAML 1.2 grammar or Falco/Tracee rule compatibility.

```yaml
id: GT-001
name: Web Server Spawned Shell
description: Shell with a currently observed web-server parent.
enabled: true
severity: high
conditions:
  parent_process:
    - nginx
    - apache2
  child_process:
    - bash
    - sh
    - dash
  exclude_parents:
    - known-allowed-parent
  exclude_children:
    - known-allowed-child
mitre:
  techniques:
    - T1059
actions:
  - alert
```

- Required keys: `id`, `name`, `enabled`, `severity`, `conditions`, `actions`.
- Required condition: `child_process`. `parent_process`, `exclude_parents`, `exclude_children` optional. Names use **exact, case-sensitive** Linux `comm` matching (up to 16-byte field; not argv or executable full path); no regex, glob or basename heuristics.
- Enabled values: `true` or `false`. Severity: `info`, `low`, `medium`, `high`, `critical`. Only `actions: - alert` is currently implemented; unsupported actions **cause a validation error** rather than a silently ignored rule. All rules can fire independently; no score or deduplication is implemented.
- Parent exclusions require an observed parent, preventing a missing-parent event from bypassing an exclusion rule. An enabled rule with parent conditions is rejected at agent startup when `enrich_procfs: false`.
- MITRE technique IDs are metadata supplied by the rule author, not independent verification of ATT&CK attribution.
- False positives are possible: simple ancestry/name conditions cannot prove compromise. No process blocking occurs.

## Commands

```bash
# Build offline-capable JSONL analyzer (does not load BPF).
make analyze

# Analyze previously recorded GhostTrace JSONL. Only alerts go to stdout.
./build/ghosttrace-analyze -rules ./rules -input ./events.jsonl > replay-alerts.jsonl

# When cilium/ebpf and BPF toolchain are installed:
make build

# Enable rule evaluation in config.yaml before running the live agent:
# rules_path: ./rules
# enrich_procfs: true
# include_executable: false

# Validate configuration & rule syntax without BPF privileges:
./build/ghosttrace-agent -config ./config.yaml -validate

# Run on a privileged isolated Linux VM only:
sudo ./build/ghosttrace-agent -config config.yaml > events.jsonl 2> agent.log
```

The analyzer checks versioned GhostTrace event format and rejects invalid JSONL, unknown fields or oversized lines (>1 MiB). It cannot manufacture absent parent/process metadata or reconstruct missing kernel events; repeating a replay generates fresh detection event IDs, so it does **not** offer exactly-once replay semantics.

## Current gaps

No fork tracepoint, reliable parent relationship at kernel hook time, network/file telemetry, time-window correlation, cross-event linking, rule hot reload, storage or dashboard. `/proc` sampling is inherently lossy for short-lived processes, restricted procfs mounts or rapidly changing PID namespaces. `PPID` may reflect a new parent after reparenting. BPF ring buffer read order is **not** guaranteed to be global event order across CPUs. Kernel capabilities and full agent build have not been tested in the provided container.

## Offline investigation filtering

`ghosttrace-query` is a separate, built CLI for stream-filtering recorded GhostTrace JSONL.

```bash
make query
./build/ghosttrace-query -input events.jsonl -type process_exec -comm sh,bash -uid 33
./build/ghosttrace-query -input alerts.jsonl -type detection_alert -severity high -rule-id GT-001
./build/ghosttrace-query -input events.jsonl -identity 'boot-id:123:456'
```

All selectors are exact and combined with AND; comma-delimited values within a selector use OR. The query reader checks schema and unknown fields, processes one record at a time (1 MiB max record), and preserves **input** order. Timestamp filters are inclusive RFC3339 bounds over userspace event timestamps; **not** reliable kernel event-time chronology. `-limit 100` stops after 100 matches, leaving the remainder unvalidated. Filters are not security controls, and should not be used as a substitute for access restrictions on event files.
