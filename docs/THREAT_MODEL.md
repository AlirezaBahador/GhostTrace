# Threat model — initial agent

## Assets

Kernel observability, agent integrity, host privacy, trusted BPF object, output log integrity, and availability of the monitored workload.

## Threat actors and trust boundaries

- An unprivileged local process can trigger very high event volume to overwhelm the collector's ring buffer, causing dropped telemetry.
- A user with control over agent configuration or its BPF object path can cause a privileged agent to load malicious BPF bytecode. Protect the executable, configuration and object with root ownership and restrictive permissions.
- A reader of event logs learns process activity metadata; logs must have appropriate access controls.
- A compromised privileged process/kernel can tamper with observation or hide activity. GhostTrace is not a defense against a fully compromised kernel.

## Existing controls

- eBPF verifier / kernel attachment permissions are required; no arbitrary command execution from the YAML config.
- Bounded kernel ring buffer; strict fixed-size binary decoder; schema validation; process-level passive monitoring only.
- Fail-fast behavior on probe attach or output failure; no claim of full telemetry if a probe is missing.

## Not yet mitigated

Agent starvation and drops under adversarial load, loss of on-disk logs, kernel compromise, PID reuse, container namespace confusion, multi-threaded process-exit ambiguity, process tree evasion, absent commandline/path context, and dependency supply-chain compromise. Further mitigations are planned and must be measured before reliability claims.
