# GhostTrace read-only JSONL API (experimental)

This API is a **real executable**, not a mock service. It reads an existing on-disk GhostTrace JSON Lines file containing validated schema-v1 records. It **does not** load eBPF, report live kernel state, keep a database, or prove that telemetry is complete. It can be used without root on Linux or any Go-supported host.

## Build and run

```bash
make server
# Use a file produced by the agent or the offline analyzer; no fabricated production events.
./build/ghosttrace-server -events ./events.jsonl -rules ./rules -listen 127.0.0.1:7766
curl -fsS 'http://127.0.0.1:7766/api/v1/events?limit=20&order=desc'
```

Start with an actual JSONL file. For example, on a compatible, privileged **Linux VM**, run the eBPF agent and redirect its stdout to a mode-0600 file. Kernel event collection in this source delivery has **not** been VM-verified. To inspect previously recorded data, start the server independently.

Optional access token, configured without command-line secret exposure:

```bash
export GHOSTTRACE_API_TOKEN="$(openssl rand -hex 32)"
./build/ghosttrace-server -events ./events.jsonl
curl -H "Authorization: Bearer $GHOSTTRACE_API_TOKEN" 'http://127.0.0.1:7766/api/v1/health'
```

Only loopback binding is accepted by the CLI; the API also rejects non-loopback HTTP `Host` headers to reduce DNS-rebinding exposure. To access from another host, use an authenticated SSH tunnel or a security-reviewed TLS reverse proxy. A token transmitted over plain HTTP to a remote host is **not** sufficient security. The API does not set permissive CORS headers. JSON responses use `Cache-Control: no-store`. The token is optional only for local-only operation.

## Endpoints (GET only)

| Endpoint | Implemented semantics |
| --- | --- |
| `/api/v1/health` | Regular JSONL file reachable and below size cap. `agent_status: unknown` is intentional. |
| `/api/v1/metrics` | Counts records and alerts **in the file only**. CPU, BPF losses, agent status are not available. |
| `/api/v1/events` | Filtered recorded event pages. |
| `/api/v1/events/{id}` | Fetch exact recorded event ID. |
| `/api/v1/alerts` | Filtered pages of `detection_alert` only. |
| `/api/v1/alerts/{id}` | Fetch alert by recorded event ID. |
| `/api/v1/processes` | List of **observed identities** with last recorded process event. Missing identities are excluded. |
| `/api/v1/processes/{id}` | Exact identity lookup; encode colon-containing identity in URLs. |
| `/api/v1/processes/{id}/tree` | Bounded observed descendant graph, not an authoritative process tree. |
| `/api/v1/rules` | Validated read-only YAML rule metadata if `-rules` is configured. |
| `/api/v1/stream` | **SSE**, not WebSocket: best-effort follow of *new appended* validated records (no history replay). |

Query options for event and alert lists: `comm`, `uid`, `type`, `identity`, `severity`, `rule_id`, `since`, `until`, `offset`, `limit`, `order`. Filters are exact matches and AND together. Time filters accept RFC3339 timestamps and filter **userspace receipt/generation** time, not a reconstructed precise kernel wall clock. Default pagination: `offset=0`, `limit=50`, `order=asc`; maximum `limit=200`, `offset=100000`. `order=desc` returns the newest records by **file insertion order** (not sorted by timestamp) and requires two sequential scans; a concurrent append may alter pagination results. For investigations requiring stable snapshots, stop writes and work on a copy.

`/api/v1/stream` uses `Content-Type: text/event-stream`. It starts at the *current file end*. New complete JSONL lines are sent as `event: event` frames; heartbeat comments are emitted. File replacement, truncation or oversize emits a `reset` event and ends the connection. Corrupt appended lines emit an `error` event and close. Clients **must** resync by querying events; SSE has no replay or at-least-once guarantee. The stream has a bounded 10-minute lifetime. This API does not provide WebSocket streaming.

## Security, resource limits, and limitations

- Only locally specified files are read; there is no file-path query parameter or arbitrary filesystem browser. Keep `events.jsonl` owner-restricted. Event metadata (paths, process command and UIDs) may be sensitive.
- The input must be a regular file, <= 64 MiB by default (`-max-file-mb` 1–1024). One JSON record is limited to 1 MiB. Files are fully scanned per request, so the API is **not a substitute for SQLite / indexed queries**.
- Four requests may execute concurrently; excess requests get HTTP 429. Normal response writes have a 15-second deadline. Requests respect cancellation. Process index is limited to 10,000 distinct identities and descendant graph to 200 nodes.
- File rotation, concurrent modification, and OS-level read permissions affect consistency. Source corruption fails closed for listing. Health only checks file reachability, not event validity.
- The API is intentionally read-only: there are no alert acknowledgments, rule updates, mutation endpoints, or admin credentials. This eliminates an entire class of write attacks while this service is experimental.
- No live agent CPU/RAM telemetry, no reliable event throughput, no kernel probe health and no dropped-event count over API. Such fields are explicitly null or unknown.

## Dashboard

The experimental React/TypeScript UI in `dashboard/` reads only these endpoints and shows no fabricated telemetry. On a network-connected development host:

```bash
cd dashboard
npm install
npm run build
cd ..
./build/ghosttrace-server -events events.jsonl -rules rules -dashboard-dir ./dashboard/dist
# Open http://127.0.0.1:7766/
```

`npm install` needs a reachable npm registry. No `package-lock.json` was generated in the offline build environment, so **the dashboard dependency lock, compile, and browser tests are outstanding**. Once dependencies are resolved, commit the generated lockfile, run `npm ci` and `npm run build` in CI. For `npm run dev`, Vite proxies `/api/` to the default loopback Go server port 7766. The token input in the dashboard is kept in browser memory, not localStorage, and used only for HTTP requests.