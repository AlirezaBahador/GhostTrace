# Security assumptions and limitations

## Privileged kernel boundary

The BPF agent requires privileges to load and attach kernel programs; deploy on a trusted Linux VM/host with the minimum tested capabilities, typically `CAP_BPF` and `CAP_PERFMON` on modern kernels (or legacy `CAP_SYS_ADMIN` where necessary). Root inside a restricted container does not confer these capabilities. Do not run as a broadly privileged Docker container. BPF ELF objects are loaded from an administrator-chosen path; ensure that object is only writable by trusted admins. Unknown/untrusted BPF programs must never be loaded into a privileged agent.

## Sensitive data

Output includes host identifiers, PIDs, effective UIDs/GIDs, process names and timing. With `enrich_procfs: true`, best-effort parent/start time metadata is also included. `include_executable: false` is the default; enable it only if capturing executable symlink paths is necessary. No file content, process arguments, environment variables, network payloads, credentials or users' file data are captured. Logs can still reveal private process and filesystem context. Run with `umask 077` when redirecting stdout and protect collected data at rest/in transit.

## Rule and input safety

- Configuration limited to 64 KiB flat YAML subset, with strict duplicate/unknown-key rejection.
- Rule files limited to 64 KiB each; up to 128 rules per directory. Unsupported syntax/actions fail configuration before attaching probes. A parser is **not** a full YAML parser; see `docs/DETECTION.md` for supported grammar.
- Only administrator-controlled config/rules directories should be used; the privileged agent reads them during startup. Do not make them writable by untrusted users.
- Offline analyzer rejects records larger than 1 MiB, unsupported schema shapes, unknown JSON fields and malformed inputs.
- Event IDs use cryptographic randomness; detection evidence refers to a previously observed event ID. Rules are static until process restart. The read-only JSONL API listens on loopback and does not expose the agent's kernel handles.

## Detection caveats

Parent and process identifiers based on procfs are best-effort and can race with reparenting, PID reuse and exit. `cached_exec_unverified` **does not** guarantee a safe correlation if a kernel record was missed. Unknown parent data causes parent-dependent rules to abstain. Name-only matching is weaker than hashing/verified executable identity, and a match is not proof of malicious activity. No response, termination or firewall change occurs.

## Loss, trust, dependencies

The ringbuf reserve-failure counter is **not** a complete lost-event rate. JSONL is synchronous and may block, and an unclean shutdown can lose events. There is no durable output queue or exactly-once guarantee. Dependency lockfiles were generated on a connected GitHub runner in the audit branch; upgraded dependency versions must be revalidated in CI. Run unit, race, static, privileged kernel and performance tests before deployment. The delivered files were not security audited and the full agent was not compiled or kernel-verified in this environment. Future network-facing backends must use authenticated TLS; this experimental backend already enforces loopback binding and loopback Host headers. The CLI now requires a Bearer token by default; unauthenticated loopback is an explicit insecure development opt-in.

## Licensing

GhostTrace is Apache-2.0. Architecture patterns were researched from public projects, but no upstream source was copied. Kunai uses GPL-3.0 and Tetragon has multiple license types: perform a component-level compatibility review and attribution before any future direct reuse.


## Experimental JSONL API and dashboard

- `cmd/server` binds **only to loopback**. Use a TLS reverse proxy / SSH tunnel for remote access; do not bind publicly and assume a bearer token makes plaintext safe. Required token is read from an environment variable and compared in constant time. Explicit `-allow-unauthenticated-loopback` mode permits any local process to read telemetry and should be used only for isolated development.
- Input path and rule path are operator-specified startup arguments, not request parameters. Source read-only operations are capped at a configured regular-file size and max record length. Up to four simultaneous API handlers are admitted. Avoid exposing a sensitive JSONL file via insecure system log rotation or filesystem permissions.
- SSE is **best effort** and can miss records on reconnect/rotation. Do not use it as a forensic audit log or replace the original stored telemetry. API process graphs and metrics describe only observed file content, not live kernel state.
- Dashboard uses React text rendering for recorded fields, never HTML injection. Token is held only in JavaScript memory; do not enter it into untrusted hosts. Self-host assets; no CDN requirement. A production dashboard build and browser security testing have **not been performed** in this offline environment.
- `deployments/systemd` and `deployments/logrotate` are **examples, not validated deployment profiles**. Capability requirements vary across kernels and distros. `copytruncate` log rotation can drop events. Check `systemd-analyze security`, runtime attach permissions, file retention and log ownership on the target host.
