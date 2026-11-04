#!/usr/bin/env bash
# Privileged live-kernel test (real Bash -> sleep parent/child relation).
# Requires the actual eBPF agent; never falls back to generated telemetry.
set -euo pipefail
cd "$(dirname "$0")/../.."
if [[ "$(uname -s)" != Linux || "$EUID" -ne 0 ]]; then
    echo 'requires privileged Linux kernel test VM' >&2; exit 2
fi
command -v python3 >/dev/null || { echo 'requires python3' >&2; exit 2; }
[[ -x build/ghosttrace-agent && -s build/process.bpf.o ]] || { echo 'run make build first' >&2; exit 2; }
workdir="$(mktemp -d)"
agent_pid=''
cleanup() {
    if [[ -n "$agent_pid" ]]; then kill -TERM "$agent_pid" 2>/dev/null || :; wait "$agent_pid" 2>/dev/null || :; fi
    rm -rf "$workdir"
}
trap cleanup EXIT
cat > "$workdir/GT-TEST.yaml" <<'YAML'
id: GT-TEST
name: Bash Spawned Sleep
description: Dedicated VM integration rule for actual process events.
enabled: true
severity: low
conditions:
  parent_process:
    - bash
  child_process:
    - sleep
actions:
  - alert
YAML
printf 'bpf_object: %s/build/process.bpf.o\nlog_level: info\nenrich_procfs: true\ninclude_executable: false\nrules_path: %s/GT-TEST.yaml\n' "$PWD" "$workdir" > "$workdir/config.yaml"
./build/ghosttrace-agent -config "$workdir/config.yaml" > "$workdir/events.jsonl" 2> "$workdir/agent.log" &
agent_pid=$!
ready=0
for ((i=0;i<80;i++)); do
    if grep -q 'probes attached' "$workdir/agent.log"; then ready=1; break; fi
    if ! kill -0 "$agent_pid" 2>/dev/null; then cat "$workdir/agent.log" >&2; exit 1; fi
    sleep 0.1
done
if [[ "$ready" != 1 ]]; then echo 'timed out attaching probes' >&2; cat "$workdir/agent.log" >&2; exit 1; fi
/bin/sleep 1.2 &
target_pid=$!
wait "$target_pid"
sleep 0.2
kill -TERM "$agent_pid"
if ! wait "$agent_pid"; then cat "$workdir/agent.log" >&2; exit 1; fi
agent_pid=''
python3 - "$workdir/events.jsonl" "$target_pid" <<'PY'
import json,sys
path,pid = sys.argv[1],int(sys.argv[2])
records=[json.loads(s) for s in open(path,encoding='utf-8') if s.strip()]
execs=[e for e in records if e['event_type']=='process_exec' and e['process']['pid']==pid]
assert execs, f'no observed real execution for pid {pid}'
alerts=[e for e in records if e['event_type']=='detection_alert' and e['process']['pid']==pid]
assert alerts, f'no detected Bash -> sleep parent/child for pid {pid}; exec={execs}'
ids={e['event_id'] for e in execs}
assert all(a['source']=='detection' and a['detection']['rule_id']=='GT-TEST' for a in alerts)
assert any(set(a['detection']['triggering_event_ids']) & ids for a in alerts)
print(f'PASS live Bash -> sleep detection for pid {pid}: {len(alerts)} alert(s)')
PY
