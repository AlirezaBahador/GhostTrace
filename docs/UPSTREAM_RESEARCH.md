# Upstream architecture review and adoption decisions

Reviewed **2026-11-04** from the four upstream public repositories and their official technical documentation. This is an architectural comparison, not a claim to have audited every line of four large, evolving codebases or reproduced all their functionality. Existing code was **not copied** into GhostTrace. Repository revision links and specific files below make the observations reproducible.

## 1. Aqua Security Tracee — policies, scopes, event taxonomy

- **Code**: https://github.com/aquasecurity/tracee (Apache-2.0).
- **Technical references**: https://aquasecurity.github.io/tracee/dev/docs/events/ and https://aquasecurity.github.io/tracee/dev/docs/policies/rules/ and https://aquasecurity.github.io/tracee/dev/docs/outputs/ .
- **Design**: a kernel-to-userspace telemetry subsystem exposes distinct event families (process, syscall, security, network, LSM, container). Policies determine event selection and filters, and output streams independently choose formats/destinations. Distinct event semantics matter: tracepoints describe events, not arbitrary successful syscall outcomes.
- **What GhostTrace actually adopted**: `include_comm`, `include_uid`, `include_event_type` userspace output filtering, explicit event-type and provenance fields, and a JSONL exporter separated from the event collector. It does **not** implement Tracee's policy language, capture engine, signature ecosystem, runtime container awareness or network/file probes.
- **Next adaptation**: eBPF-level filters and event-specific telemetry (TCP attempts, file activity) **only after** hook-level verification. Explicitly label attempted vs completed operations.

## 2. Cilium Tetragon — process identity, lifecycle, bounded process state

- **Code**: https://github.com/cilium/tetragon (multilicensed repository: Apache-2.0, BSD and GPL components; per-file licenses must be verified before reuse).
- **Technical references**: https://tetragon.io/docs/use-cases/process-lifecycle/ and https://tetragon.io/docs/use-cases/process-lifecycle/process-execution/ and https://tetragon.io/docs/concepts/tracing-policy/ .
- **Specific source reviewed**: [`pkg/process/cache.go`](https://github.com/cilium/tetragon/blob/main/pkg/process/cache.go), a bounded LRU process cache with asynchronous garbage collection and safeguards for delayed/out-of-order events. This is particularly relevant to `exec->exit->connect` ordering and preserving recently exited process context. No source was transplanted.
- **Design**: process execution identity (`exec_id`), parent relationship, process start time, and lifecycle association are first-class. Kubernetes-aware enrichment is optional deployment context rather than a requirement to emit raw process events. Tetragon also offers generic tracing policies and optional kernel enforcement.
- **What GhostTrace actually adopted**: opt-in procfs-related process enrichment, ID derived from **host boot ID + PID + /proc starttime ticks**, conservative best-effort parent observation, and bounded in-memory tracking with PID replacement. A cached exit **explicitly says** `cached_exec_unverified` because a missing event or PID reuse can invalidate it.
- **What GhostTrace did NOT adopt**: kernel-captured start time, reliable fork ancestry, reordering-safe deferred deletion, persistent process history, process exec `exec_id` semantics, kprobes/LSM policy loading, or enforcement. A procfs-sampled parent can be different from the parent at hook time; detection fails closed when parent is unavailable.
- **Next adaptation**: add fork telemetry and kernel task birth times, test PID reuse and leader-exit edge cases in a privileged VM before claiming authoritative process ancestry. Keep monitoring-only even though Tetragon supports enforcement.

## 3. Falco — declarative rule semantics and explanatory alerts

- **Code**: https://github.com/falcosecurity/falco (Apache-2.0; Falco also uses `falcosecurity/libs`, `rules`, and `plugins`).
- **Technical references**: https://falco.org/docs/concepts/rules/ and https://falco.org/docs/concepts/rules/exceptions/ and https://falco.org/docs/concepts/metrics/ .
- **Specific source reviewed**: [`userspace/falco/configuration.cpp`](https://github.com/falcosecurity/falco/blob/master/userspace/falco/configuration.cpp), which exposes drop thresholds, event-output settings, buffering, per-rule settings, and structured configuration handling. GhostTrace uses none of its source.
- **Design**: YAML rules encode conditions, severity, output, and exceptions; list/macro structures factor out common predicates. Reliable monitoring reports kernel and userspace event loss as separate dimensions. Rules are bound to actual event semantics.
- **What GhostTrace actually adopted**: a small validated, opt-in YAML rule grammar (not Falco's condition expression syntax), severity/enabled/MITRE fields, process and parent conditions, conditional name exceptions, evidence-linked structured alert events, and fail-closed unknown/unsupported rule operations.
- **What GhostTrace did NOT adopt**: full Falco macros/lists/filter language, runtime hot reload, syscall selection, plugins, detection rate limits, multi-event expressions, snapshot capture, complete metrics, or compatibility with official Falco rules. Current drop counter captures **only BPF ringbuf reservation failures**.
- **Next adaptation**: add verified telemetry sources before broadening rule grammar and alert correlation; add metrics and measured loss under pressure.

## 4. Kunai — host-oriented investigation, enriched event context

- **Code**: https://github.com/kunai-project/kunai (**GPL-3.0**; DO NOT copy GPL code into this Apache-2.0 repository without an explicit compatible licensing arrangement).
- **Technical references**: https://why.kunai.rocks/docs/events/generalities/ and https://why.kunai.rocks/docs/events/ .
- **Specific source reviewed**: [`kunai/src/events.rs`](https://github.com/kunai-project/kunai/blob/main/kunai/src/events.rs): common event/host/task sections, identifiers, and typed data families. The tool's README describes Rust + Aya eBPF components and host-side event reordering/correlation.
- **Design**: a common event envelope carries process-group identity across types, with time-ordering and host-side correlation/enrichment. Published event families span exec, clone, connect, DNS, file modifications, defensive investigations, and event loss. Its "chronologically ordered" promise requires explicit buffering/reordering beyond merely reading a BPF ring buffer.
- **What GhostTrace actually adopted**: common versioned event envelope, host boot identity, optional parent/exec metadata, per-event provenance, offline JSONL alert analysis, a verified streaming `ghosttrace-query` investigation tool and bounded state.
- **What GhostTrace did NOT adopt**: guaranteed chronology, socket/DNS/file events, container awareness, file hashes, rich threat-hunting rule ecosystem, or its event ID generation algorithm. `kernel_monotonic_ns` is preserved for kernel records, but event processing order is **not** guaranteed global monotonic order across CPUs.

## Capability/status matrix

| Capability inspired by upstream | Current GhostTrace state | Required additional work |
| --- | --- | --- |
| Tracee-style explicit event categories | **Implemented**: exec, leader exit, detection alert | Network/file event categories and hooks not implemented |
| Tracee-like scoped telemetry filter | **Implemented**: `include_comm`, `include_uid`, `include_event_type` filter raw JSONL only | In-kernel UID/path/event-type selectors and workload policies |
| Tetragon-style stable process ID | **Experimental**: procfs start ticks + boot ID + PID on live exec | Kernel-derived identity, robust fork and event loss accounting |
| Tetragon-style ancestry | **Experimental**: live procfs parent observation | Fork events, reparenting, delayed events, process tree history |
| Falco-style declarative YAML detection | **Implemented subset**: strict YAML single-event rules | Full YAML parser / expression DSL / multi-event rules |
| Falco-style exceptions | **Implemented subset**: process-name exclusions | Actor/operation/target scoped exceptions |
| Falco-style event loss | **Implemented in BPF source**, kernel test **NOT RUN** | Reader/drop-rate metrics, dynamic pressure benchmark |
| Kunai-style common event identity | **Implemented**: schema, event UUID, host boot ID | Full task-group ID, namespace/container IDs |
| Kunai-style offline hunting | **Implemented**: `ghosttrace-analyze` and `ghosttrace-query` on validated JSONL | Query/index storage, timeline/reordering, investigator UI |
| Kunai-style extensive telemetry | **Not implemented** | Network, file, privilege, namespace hooks and tests |
| Tetragon runtime enforcement | **Intentionally excluded** from GhostTrace 0.1 | Security product decision, not a missing MVP requirement |

## Priorities (dependency order)

1. **Release gate**: obtain BPF backend/compiler, resolve `cilium/ebpf` with a lockfile, build full agent and run the privileged exec/exit integration tests.
2. **Identity correctness**: kernel start-time/fork telemetry, process leader-exit semantics, PID reuse + missing-event tests before confident lineage.
3. **Network telemetry**: instrument *outbound TCP connect attempts* and separately observed outcomes, including IPv6 evaluation; no "established" claim without evidence.
4. **File telemetry**: clearly distinguish open/access attempts from successful reads or writes; configurable sensitive-path policies; no file contents.
5. **Correlated detections**: explicit time windows, retained evidence and loss-aware confidence, exclusions keyed to actor/action/target.
6. **Persistence/API/UI**: SQLite with retention then localhost auth API, then dashboard; no fake telemetry.
7. **Performance/security hardening**: measured overhead and loss, CI VM tests, external review, systemd packaging.

## Licensing/attribution policy

Design patterns and publicly documented behavior informed this implementation, but no upstream code, rules, static datasets or generated files were copied. Any later upstream source incorporation requires explicit file-level license review, attribution, NOTICE obligations where applicable and compatibility review (particularly Kunai GPL-3.0 and Tetragon's mixed licenses). GhostTrace's own implementation remains Apache-2.0.

## Upstream source-level review snapshot (2026-11-04)

Besides public documentation, the following **specific current code paths** were inspected for design patterns, without copying code:

- Tracee: [`api/v1beta1/event.proto`](https://github.com/aquasecurity/tracee/blob/main/api/v1beta1/event.proto) separates event identity, workload process ancestry, host/container context, and threat/detection data. This supports GhostTrace's own distinct `event_type`, optional process metadata and detection evidence, **not** protobuf/wire compatibility.
- Tetragon: [`pkg/process/cache.go`](https://github.com/cilium/tetragon/blob/main/pkg/process/cache.go) manages an LRU process cache and deferred GC in the presence of out-of-order events. GhostTrace has a smaller PID-keyed bounded cache but does **not** claim the same lifecycle guarantees.
- Falco: [`userspace/falco/configuration.cpp`](https://github.com/falcosecurity/falco/blob/master/userspace/falco/configuration.cpp) configures detection-related output and loss instrumentation. GhostTrace's output filtering and `ringbuf_drops` are much narrower; Falco-style exception scoping and loss thresholds remain planned.
- Kunai: [`kunai/src/events.rs`](https://github.com/kunai-project/kunai/blob/main/kunai/src/events.rs) maintains common event + host/task identity; its GPL-3.0 code was **not imported**. GhostTrace adapted the *concept* of stable event envelope and offline investigation, not implementation details or any compatible event guarantee.

**Scope warning:** this review covers selected architecture-critical source files and documented features, **not** a line-by-line audit of all four upstream repositories. These are mature, large products; all of their capabilities cannot be incorporated safely into an unverified v0.1 release. Subsequent features must be built and tested one milestone at a time.