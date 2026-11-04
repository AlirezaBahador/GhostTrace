SHELL := /bin/bash
GO ?= go
CLANG ?= clang
ARCH := $(shell uname -m)
MULTIARCH := $(shell gcc -dumpmachine 2>/dev/null)
BPF_CFLAGS := -O2 -g -Wall -Werror -target bpf -Iebpf/include -I/usr/include/$(MULTIARCH)

.PHONY: all bpf build analyze query server test test-userspace test-userspace-race vet fmt integration clean
all: build

build: bpf
	$(GO) build -trimpath -o build/ghosttrace-agent ./cmd/agent

bpf: build/process.bpf.o

build/process.bpf.o: ebpf/process.bpf.c ebpf/include/gt_bpf_helpers.h
	@mkdir -p build
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Offline-checkable components do not need cilium/ebpf packages.
USERSPACE_PACKAGES := ./cmd/analyze ./cmd/query ./cmd/server ./internal/api ./internal/eventio ./internal/filter ./internal/agent ./internal/config ./internal/decoder ./internal/detection ./internal/exporter ./internal/process ./pkg/events

analyze:
	@mkdir -p build
	$(GO) build -trimpath -o build/ghosttrace-analyze ./cmd/analyze

query:
	@mkdir -p build
	$(GO) build -trimpath -o build/ghosttrace-query ./cmd/query

server:
	@mkdir -p build
	$(GO) build -trimpath -o build/ghosttrace-server ./cmd/server

test-userspace:
	$(GO) test -count=1 $(USERSPACE_PACKAGES)

test-userspace-race:
	$(GO) test -race -count=1 $(USERSPACE_PACKAGES)

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -w cmd internal pkg

integration: build
	bash tests/integration/process.sh

clean:
	rm -rf build
