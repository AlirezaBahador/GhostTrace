#!/usr/bin/env bash
# Privileged real-kernel test; NO synthetic events. Run inside an isolated VM.
set -euo pipefail
cd "$(dirname "$0")/../.."
if [[ "$(uname -s)" != Linux ]]; then echo 'requires Linux' >&2; exit 2; fi
if [[ "$EUID" -ne 0 ]]; then echo 'requires root with eBPF and perf privileges' >&2; exit 2; fi
command -v python3 >/dev/null || { echo 'requires python3' >&2; exit 2; }
[[ -x build/ghosttrace-agent ]] || { echo 'run make build first' >&2; exit 2; }
workdir="$(mktemp -d)"
agent_pid=''
cleanup() {
    if [[ -n "$agent_pid" ]]; then kill -TERM "$agent_pid" 2>/dev/null || :; wait "$agent_pid" 2>/dev/null || :; fi
    rm -rf "$workdir"
}
trap cleanup EXIT
./build/ghosttrace-agent -config config.yaml >"$workdir/events.jsonl" 2>"$workdir/agent.log" &
agent_pid=$!
ready=0
for ((i=0;i<60;i++)); do
    if grep -q 'probes attached' "$workdir/agent.log"; then ready=1; break; fi
    if ! kill -0 "$agent_pid" 2>/dev/null; then cat "$workdir/agent.log" >&2; echo 'agent exited before probes attached' >&2; exit 1; fi
    sleep 0.1
done
if [[ "$ready" -ne 1 ]]; then cat "$workdir/agent.log" >&2; echo 'agent startup timed out' >&2; exit 1; fi
/bin/sleep 0.3 &
target_pid=$!
wait "$target_pid"
sleep 0.5
kill -TERM "$agent_pid"
if ! wait "$agent_pid"; then cat "$workdir/agent.log" >&2; echo 'agent shutdown failed' >&2; exit 1; fi
agent_pid=''
python3 - "$workdir/events.jsonl" "$target_pid" <<'PY'
import json,sys
path,pid=sys.argv[1],int(sys.argv[2])
events=[]
with open(path,encoding='utf-8') as stream:
    for line in stream:
        e=json.loads(line)
        assert e['source']=='ebpf' and e['schema_version']=='1.0'
        assert e['timestamp_source']=='userspace_receive'
        assert e['host']['boot_id'] and e['event_id']
        events.append(e)
kind={e['event_type'] for e in events if e['process']['pid']==pid}
assert {'process_exec','process_exit'} <= kind, f'pid {pid}: observed {kind}, total events {len(events)}'
print(f'PASS real Linux exec+exit probe: pid={pid}, captured JSONL records={len(events)}')
PY
