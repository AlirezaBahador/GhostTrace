// ghosttrace-query streams validated events out of an existing GhostTrace
// JSONL file; it is not a real-time collector or a persistent database.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ghosttrace/ghosttrace/internal/eventio"
	"github.com/ghosttrace/ghosttrace/internal/exporter"
	"github.com/ghosttrace/ghosttrace/internal/filter"
	"github.com/ghosttrace/ghosttrace/pkg/events"
)

const MaxSelectors = 64

func csvValues(s string) (map[string]bool, error) {
	if s == "" {
		return nil, nil
	}
	values := strings.Split(s, ",")
	if len(values) > MaxSelectors {
		return nil, fmt.Errorf("too many selectors (limit %d)", MaxSelectors)
	}
	result := make(map[string]bool, len(values))
	for _, v := range values {
		if v == "" || strings.TrimSpace(v) != v || len(v) > 256 || result[v] {
			return nil, fmt.Errorf("invalid or repeated selector %q", v)
		}
		result[v] = true
	}
	return result, nil
}

func parsePolicy(comm, uid, kind, identity, ruleID, severity, since, until string) (filter.Policy, error) {
	p := filter.Policy{}
	var err error
	for _, item := range []struct {
		s    string
		dest *map[string]bool
	}{
		{comm, &p.Comms}, {kind, &p.EventTypes}, {identity, &p.Identities}, {ruleID, &p.RuleIDs}, {severity, &p.Severities},
	} {
		*item.dest, err = csvValues(item.s)
		if err != nil {
			return p, err
		}
	}
	uids, err := csvValues(uid)
	if err != nil {
		return p, err
	}
	if len(uids) > 0 {
		p.UIDs = make(map[uint32]bool, len(uids))
		for raw := range uids {
			if len(raw) > 1 && raw[0] == '0' {
				return p, fmt.Errorf("invalid UID %q", raw)
			}
			parsed, e := strconv.ParseUint(raw, 10, 32)
			if e != nil {
				return p, fmt.Errorf("invalid UID %q: %w", raw, e)
			}
			p.UIDs[uint32(parsed)] = true
		}
	}
	if since != "" {
		p.Since, err = time.Parse(time.RFC3339Nano, since)
		if err != nil {
			return p, fmt.Errorf("invalid since: %w", err)
		}
	}
	if until != "" {
		p.Until, err = time.Parse(time.RFC3339Nano, until)
		if err != nil {
			return p, fmt.Errorf("invalid until: %w", err)
		}
	}
	if err := p.Validate(); err != nil {
		return p, err
	}
	return p, nil
}

func Query(ctx context.Context, in io.Reader, out io.Writer, p filter.Policy, limit int) (int, error) {
	if err := p.Validate(); err != nil {
		return 0, err
	}
	if limit < 0 {
		return 0, fmt.Errorf("negative limit")
	}
	sink := exporter.NewJSONL(out)
	matched := 0
	_, err := eventio.Visit(ctx, in, func(e events.Event) (bool, error) {
		if !p.Match(e) {
			return true, nil
		}
		if err := sink.Write(ctx, e); err != nil {
			return false, err
		}
		matched++
		return limit == 0 || matched < limit, nil
	})
	return matched, err
}

func run() int {
	input := flag.String("input", "-", "input validated GhostTrace JSONL (- for stdin)")
	comm := flag.String("comm", "", "exact process command names (comma separated)")
	uid := flag.String("uid", "", "numeric process UIDs (comma separated)")
	kind := flag.String("type", "", "event types: process_exec,process_exit,detection_alert")
	identity := flag.String("identity", "", "exact process identity")
	ruleID := flag.String("rule-id", "", "rule IDs on detection alerts")
	severity := flag.String("severity", "", "severity on detection alerts")
	since := flag.String("since", "", "timestamp lower bound, RFC3339 (inclusive)")
	until := flag.String("until", "", "timestamp upper bound, RFC3339 (inclusive)")
	limit := flag.Int("limit", 0, "maximum matched output events (0 = all)")
	flag.Parse()
	p, err := parsePolicy(*comm, *uid, *kind, *identity, *ruleID, *severity, *since, *until)
	if *limit < 0 {
		err = fmt.Errorf("limit must be non-negative")
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "ghosttrace-query: invalid filter: %v\n", err)
		return 2
	}
	var in io.Reader = os.Stdin
	if *input != "-" {
		f, err := os.Open(*input)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ghosttrace-query: input: %v\n", err)
			return 2
		}
		defer f.Close()
		in = f
	}
	matched, err := Query(context.Background(), in, os.Stdout, p, *limit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ghosttrace-query: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "ghosttrace-query: emitted %d matching events\n", matched)
	return 0
}
func main() { os.Exit(run()) }
