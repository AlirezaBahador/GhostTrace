#!/usr/bin/env bash
# Unprivileged HTTP smoke test with an EMPTY recorded file. No synthetic kernel
# telemetry and no claim of agent integration. Requires curl and built server.
set -euo pipefail
cd "$(dirname "$0")/../.."
[[ -x build/ghosttrace-server ]] || { echo 'run make server first' >&2; exit 2; }
command -v curl >/dev/null || { echo 'curl required' >&2; exit 2; }
workdir="$(mktemp -d)"
trap '[[ -n "${pid:-}" ]] && kill -TERM "$pid" 2>/dev/null || :; rm -rf "$workdir"' EXIT
chmod 0700 "$workdir"
: > "$workdir/events.jsonl"
chmod 0600 "$workdir/events.jsonl"
# Choose a loopback port and ensure an occupied port fails rather than exiting
# successfully with the wrong server. A VM may choose another local port.
port="${GHOSTTRACE_API_TEST_PORT:-17766}"
./build/ghosttrace-server -events "$workdir/events.jsonl" -listen "127.0.0.1:$port" > "$workdir/server.log" 2>&1 &
pid=$!
ready=0
for ((i=0;i<30;i++)); do
  if ! kill -0 "$pid" 2>/dev/null; then cat "$workdir/server.log" >&2; exit 1; fi
  if curl -fsS "http://127.0.0.1:$port/api/v1/health" > "$workdir/health.json"; then ready=1; break; fi
  sleep 0.1
done
[[ "$ready" == 1 ]] || { echo 'API startup failed' >&2; exit 1; }
curl -fsS "http://127.0.0.1:$port/api/v1/events?order=desc&limit=3" > "$workdir/events-response.json"
curl -fsS "http://127.0.0.1:$port/api/v1/metrics" > "$workdir/metrics.json"
python3 - "$workdir" <<'PY'
import json,sys,pathlib
base=pathlib.Path(sys.argv[1])
health=json.loads((base/'health.json').read_text())
page=json.loads((base/'events-response.json').read_text())
metrics=json.loads((base/'metrics.json').read_text())
assert health['mode']=='recorded_jsonl' and health['agent_status']=='unknown'
assert page['items']==[] and page['total']==0
assert metrics['recorded_events']==0 and metrics['recorded_alerts']==0
assert metrics['kernel_drops'] is None
print('PASS empty-file API HTTP smoke (not eBPF telemetry)')
PY
kill -TERM "$pid"
wait "$pid"
pid=''
