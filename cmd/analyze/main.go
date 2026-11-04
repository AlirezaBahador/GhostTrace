// ghosttrace-analyze evaluates the same rules as the agent against existing
// versioned GhostTrace JSONL. It never claims to collect live kernel events.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/ghosttrace/ghosttrace/internal/detection"
	"github.com/ghosttrace/ghosttrace/internal/eventio"
	"github.com/ghosttrace/ghosttrace/internal/exporter"
	"github.com/ghosttrace/ghosttrace/pkg/events"
)

const MaxJSONLine = eventio.MaxLine

func Analyze(ctx context.Context, input io.Reader, output io.Writer, engine *detection.Engine) (int, error) {
	if engine == nil {
		return 0, fmt.Errorf("no detection engine")
	}
	sink := exporter.NewJSONL(output)
	alerts := 0
	_, err := eventio.Visit(ctx, input, func(e events.Event) (bool, error) {
		found, err := engine.Evaluate(e)
		if err != nil {
			return false, fmt.Errorf("detection: %w", err)
		}
		for _, alert := range found {
			if err := sink.Write(ctx, alert); err != nil {
				return false, fmt.Errorf("write alert: %w", err)
			}
			alerts++
		}
		return true, nil
	})
	return alerts, err
}

func run() int {
	path := flag.String("rules", "rules", "path to validated rules file or directory")
	inputPath := flag.String("input", "-", "input GhostTrace JSONL (- for standard input)")
	flag.Parse()
	rules, err := detection.Load(*path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ghosttrace-analyze: invalid rules: %v\n", err)
		return 2
	}
	engine, err := detection.New(rules)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ghosttrace-analyze: invalid rules: %v\n", err)
		return 2
	}
	input := io.Reader(os.Stdin)
	if *inputPath != "-" {
		f, err := os.Open(*inputPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ghosttrace-analyze: input: %v\n", err)
			return 2
		}
		defer f.Close()
		input = f
	}
	count, err := Analyze(context.Background(), input, os.Stdout, engine)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ghosttrace-analyze: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "ghosttrace-analyze: emitted %d detection alerts\n", count)
	return 0
}

func main() { os.Exit(run()) }
