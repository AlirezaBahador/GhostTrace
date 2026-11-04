//go:build linux && (amd64 || arm64)

package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/AlirezaBahador/GhostTrace/internal/agent"
	"github.com/AlirezaBahador/GhostTrace/internal/collector"
	"github.com/AlirezaBahador/GhostTrace/internal/config"
	"github.com/AlirezaBahador/GhostTrace/internal/detection"
	"github.com/AlirezaBahador/GhostTrace/internal/exporter"
	"github.com/AlirezaBahador/GhostTrace/internal/process"
	"github.com/AlirezaBahador/GhostTrace/pkg/events"
)

func main() { os.Exit(run()) }

func run() int {
	configPath := flag.String("config", "config.yaml", "path to flat YAML config")
	validateOnly := flag.Bool("validate", false, "validate config and rules without loading eBPF")
	flag.Parse()
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ghosttrace: configuration error: %v\n", err)
		return 2
	}
	var detector *detection.Engine
	var nRules int
	if cfg.RulesPath != "" {
		rules, err := detection.Load(cfg.RulesPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ghosttrace: rules error: %v\n", err)
			return 2
		}
		nRules = len(rules)
		if !cfg.EnrichProcfs {
			for _, rule := range rules {
				if rule.Enabled && (len(rule.Conditions.ParentProcess) > 0 || len(rule.Conditions.ExcludeParents) > 0) {
					fmt.Fprintf(os.Stderr, "ghosttrace: rule %s requires enrich_procfs: true for parent conditions\n", rule.ID)
					return 2
				}
			}
		}
		detector, err = detection.New(rules)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ghosttrace: rules error: %v\n", err)
			return 2
		}
	}
	if *validateOnly {
		fmt.Fprintf(os.Stderr, "ghosttrace: valid config; loaded %d rules\n", nRules)
		return 0
	}
	level := slog.LevelInfo
	switch cfg.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	host, err := events.LocalHost()
	if err != nil {
		logger.Error("host identity", "error", err)
		return 1
	}
	source, err := collector.Open(cfg.BPFObject)
	if err != nil {
		logger.Error("start eBPF collection", "error", err)
		return 1
	}
	defer func() {
		if err := source.Close(); err != nil {
			logger.Error("close collector", "error", err)
		}
	}()
	logger.Info("probes attached", "object", cfg.BPFObject, "hooks", "sched_process_exec,sched_process_exit")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	filter := make(map[string]bool, len(cfg.IncludeComm))
	for _, name := range cfg.IncludeComm {
		filter[name] = true
	}
	uidFilter := make(map[uint32]bool, len(cfg.IncludeUID))
	for _, uid := range cfg.IncludeUID {
		uidFilter[uid] = true
	}
	typeFilter := make(map[string]bool, len(cfg.IncludeEventType))
	for _, typ := range cfg.IncludeEventType {
		typeFilter[typ] = true
	}
	opts := agent.Options{Detector: detector, IncludeComm: filter, IncludeUID: uidFilter, IncludeEventType: typeFilter}
	if cfg.EnrichProcfs {
		opts.Enricher = process.New(4096).WithExecutable(cfg.IncludeExecutable)
	}
	stats, runErr := agent.RunWithOptions(ctx, source, exporter.NewJSONL(os.Stdout), host, opts)
	drops, dropErr := source.Drops()
	if dropErr != nil {
		logger.Error("read kernel ring-buffer drop counter", "error", dropErr)
	}
	logger.Info("agent stopped", "emitted_events", stats.Emitted, "alerts", stats.Alerts, "filtered_events", stats.Filtered, "loaded_rules", nRules, "bpf_ringbuf_reserve_failures", drops)
	if runErr != nil {
		logger.Error("agent failure", "error", runErr)
		return 1
	}
	if dropErr != nil {
		return 1
	}
	return 0
}
