# Security assumptions and limitations

## Trust and privileges

GhostTrace attaches Linux eBPF tracepoints from a privileged process. BPF loading is a kernel attack surface; run on trusted kernels and maintain Go/Clang dependencies. Do not run the agent inside a broadly privileged container. On kernels with fine-grained privilege control, grant only capabilities required for BPF program load and tracepoint attachment (commonly CAP_BPF and CAP_PERFMON); the actual requirements depend on distribution policy. The program does not request escalation or alter firewall / process state.

## Data protection

The JSONL stream includes process name, numeric UID/GID, host/boot identity, PID, monotonic time and UTC receive time. Process names and timing may be sensitive. Redirect stdout to a restricted file and protect collected logs under a restrictive `umask` (for example `umask 077`) or a host-managed logging service. `events.jsonl` in README is an example path, not an automatically secured database. GhostTrace never reads file contents or environment variables. It does not export arguments or executable paths in v0.1.

## Input safety

Configuration is capped at 64 KiB; only two top-level keys in a restricted flat YAML subset are accepted. Missing/duplicate/unknown keys fail closed. The BPF object path is selected by an administrator and should be writable only by a trusted administrator; a malicious eBPF object is a serious threat. The decoder validates lengths, reserved fields, IDs and enum values. A malformed kernel record causes the agent to fail rather than silently reinterpret data.

## Reliability and failure modes

Failure to read the BPF object, load maps, or attach either hook aborts startup. JSON write failures are fatal. The 1 MiB ring buffer bounds backlog but does not prevent loss. The `ringbuf_drops` metric counts only failed kernel reservations, **not** all imaginable missing events, and it is logged when the agent shuts down. The agent does not claim complete host visibility or endpoint protection.

## Known open security work

Production deployment still requires pinned/verifiable dependencies (`go.sum` is not yet generated), a tested packaging scheme, distro-by-distro capability restrictions, privileged integration testing, external audit, release signing, and load/performance testing. No remote server or API authentication exists yet because there is no API in phase 1.

Please report security concerns privately to the repository maintainer once a public security contact has been established; do not publish exploit details or private host telemetry in issues.