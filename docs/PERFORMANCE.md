# Performance methodology

**No end-to-end agent, kernel event-loss, or monitored-workload overhead benchmark has run.** Two separately labeled *userspace microbenchmarks* were executed on 2026-11-04; they are **not agent performance numbers**.

## Proposed controlled Linux VM benchmark

Record: distro and exact kernel version, Go and clang versions, CPU model/core count, RAM, BTF availability, container/VM configuration, exact agent commit, BPF object hash, workload details, and duration.

Compare three conditions with the **same workload**:

1. Baseline: agent absent.
2. GhostTrace process event collection and JSONL export enabled.
3. GhostTrace with rules/detection enabled (future phase; **unavailable now**).

Collect: host CPU load, agent CPU and peak RSS, events/s from agent and externally generated process executions, BPF map memory (`bpftool` where available), ring-buffer failed reserves, read latency, storage growth, and workload throughput/latency. Repeat runs and report uncertainty and variance, not just one best case. Event counts should be cross-checked against a deterministic process spawning workload; no synthetic events should enter the production data path.

Potential measurement tools: `/usr/bin/time -v`, `pidstat`, `perf stat`, `bpftool map show`, `stat`, a real process-execution workload, and limited kernel tracing on the test VM. Publishing benchmark commands and raw observations is required before adding headline overhead or loss numbers.

## Current observations

The ring-buffer map max size is statically configured to **1 MiB**; this is a configuration value, **not** a measured memory footprint. There is one 64-bit drop counter map entry. No measurements of workload overhead, throughput, latency or end-to-end loss are available.


## Userspace microbenchmark results (real measurements, synthetic fixtures)

Command executed:

```bash
GOPROXY=off go test -run '^$' -bench '^Benchmark' -benchmem -count=1 ./internal/decoder ./internal/detection
```

Environment: Debian GNU/Linux 13, Linux kernel 6.18.57 (container), Go 1.23.2, Linux/amd64; CPU exposed by host: **AMD EPYC 9V74 80-Core Processor**. `GOMAXPROCS` was controlled by the Go test runner (bench labels `-5`); exact VM affinity, scheduler noise and CPU frequency are uncontrolled. Single observed run:

| Benchmark | ns/op | B/op | allocs/op |
| --- | ---: | ---: | ---: |
| `BenchmarkDecode-5` | 26.98 | 8 | 1 |
| `BenchmarkRuleMatchNoHit-5` | 14.48 | 0 | 0 |

Both are **unit-test fixtures**, not kernel records. Decode covers one fixed, valid 48-byte synthetic event. Rule matching covers one negative-match case and does not generate an alert. Neither measures cost of JSON serialization, procfs enrichment, process start/exit hooks, event drops, full pipeline throughput, detection latency, or production CPU/memory overhead. Results may vary and should not be presented as a representative host workload benchmark. The end-to-end measurements above remain **NOT RUN**.
