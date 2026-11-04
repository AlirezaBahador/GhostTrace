# Development and verification workflow

## Commands

```sh
go fmt ./...
go test -race ./...
go vet ./...
make build CLANG=/usr/bin/clang
sudo bash tests/integration/process.sh  # isolated VM only
```

The kernel integration script is **privilege-gated**: it exits with an error if it cannot execute the actual collector. Do not classify unavailable Linux capabilities as passing tests. The workflow `.github/workflows/go.yml` does NOT perform privileged telemetry verification.

## Dependency lock and initial publication

The module currently declares `github.com/cilium/ebpf v0.17.3`. The build environment used for this initial source delivery cannot reach Go's module proxy, so a verified `go.sum` could not be generated. **Before tagging v0.1.0**, on a network-connected trusted machine run:

```sh
go mod tidy
go mod verify
go test ./...
git add go.mod go.sum
```

Review dependency transitive versions and security advisories before committing and releasing. Commit `go.sum` for reproducibility; dependency resolution is an **outstanding validation task**. Never handcraft checksums.

## Protocol compatibility

`ebpf/process.bpf.c` and `internal/decoder/process.go` share a strict 48-byte wire format. For every layout edit: update the size assertion, offsets, encoder/decoder tests and JSON schema semantics. Avoid inferring additional fields from PID alone.

## Design rules

- Keep the agent operable without a UI, API server, or database.
- No simulated kernel events in production; fixtures and fake `Source` implementations are allowed only in tests.
- Don't silently swallow probe attach errors or JSON encoder failures.
- Keep BPF memory and Go state bounded, log drops and partial-visibility caveats.
- Write isolated unit tests before broad kernel integration tests.
- Prefer straightforward Linux kernel tracepoints over unstable kprobes without a reason.

## Initial environment constraints

The source was written in a Debian 13 container with Go 1.23.2, Linux host kernel 6.18.57, and Swift Clang 17, which has **no BPF code-generation target**. The container also has no readable `/sys/kernel/btf/vmlinux` or effective CAP_BPF/CAP_PERFMON; DNS to `proxy.golang.org` is blocked. As a result, only the standard-library-dependent packages could be compiled/vetted/tested locally, and host C syntax was checked without BPF codegen. No kernel probe was loaded or attached. Do not describe Phase 1 as a verified v0.1.0 release until a suitable Linux VM finishes the build/integration steps.

## Post-Phase-1 userspace extensions (2026-11-04)

`make analyze` builds the unprivileged `ghosttrace-analyze` CLI. `make test-userspace` and `make test-userspace-race` cover the decoder, enrichment, strict YAML rule validation, alert construction and offline analyzer without loading `cilium/ebpf`. `make build` still requires the BPF-capable Clang and a network-resolved Go module lockfile; do not mark it passing if missing.

The parent enrichment is read from `/proc` rather than the kernel hook and is not authoritative. Test negative cases for disappearing tasks, PID reuse and missing parents. Avoid adding new eBPF hook semantics before verifying the correct attach point and outcome/attempt distinction. `sudo bash tests/integration/detection.sh` is an additional VM-only real-kernel test, not an unprivileged simulation.


## Offline JSONL API and optional web UI

```sh
make server analyze query
./build/ghosttrace-server -events /path/to/recorded/events.jsonl -rules rules
curl 'http://127.0.0.1:7766/api/v1/metrics'
```

Read `docs/API.md` for endpoint contracts and source semantics. Dashboard source is experimental; install dependencies on a connected host with `cd dashboard && npm install`, create/commit `package-lock.json`, and then run `npm run build` and browser tests. This environment could not perform the npm step. Run all available standard-library unit packages locally with `make test-userspace test-userspace-race`, but do not treat those results as eBPF kernel validation.
