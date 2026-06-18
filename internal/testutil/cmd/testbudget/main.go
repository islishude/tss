// testbudget parses `go test -json` output from stdin and flags individual
// tests that exceed their tier's runtime budget. Budgets are defined in
// docs/testing-rules.md:
//
//	Tier 0: 500ms    Tier 1: 5s    Integration: 60s
//
// Usage:
//
//	go test -json ./... | go run ./internal/testutil/cmd/testbudget
//	go test -json -tags=integration ./cggmp21/secp256k1 | go run ./internal/testutil/cmd/testbudget -tier=integration -top=50 -leaves -fail=false
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
)

// Tier budgets as defined in docs/testing-rules.md.
const (
	tier0Budget       = 500 * time.Millisecond
	tier1Budget       = 5 * time.Second
	integrationBudget = 60 * time.Second
)

type testEvent struct {
	Time    time.Time `json:"Time"`
	Action  string    `json:"Action"`
	Package string    `json:"Package"`
	Test    string    `json:"Test"`
	Elapsed float64   `json:"Elapsed"` // seconds
	Output  string    `json:"Output"`
}

type testRecord struct {
	Package string
	Test    string
	Tier    string
	Budget  time.Duration
	Elapsed time.Duration
	Violate bool
}

type options struct {
	topN            int
	forceTier       string
	leavesOnly      bool
	failOnViolation bool
}

// tierForPackage maps a package path to a tier label and budget. Returns
// ("", 0, false) for packages that have no budget enforcement.
func tierForPackage(pkg string) (string, time.Duration, bool) {
	switch {
	case strings.Contains(pkg, "slowcrypto"):
		return "slowcrypto", 0, false
	case isIntegrationPackage(pkg) || strings.Contains(pkg, "securekey") || strings.Contains(pkg, "integration"):
		return "integration", integrationBudget, true
	case isTier1Package(pkg):
		return "tier1", tier1Budget, true
	default:
		return "tier0", tier0Budget, true
	}
}

func isIntegrationPackage(pkg string) bool {
	integrationPrefixes := []string{
		"github.com/islishude/tss/cggmp21/secp256k1",
		"github.com/islishude/tss/frost/ed25519",
	}
	for _, prefix := range integrationPrefixes {
		if strings.HasPrefix(pkg, prefix) {
			return true
		}
	}
	return false
}

func isTier1Package(pkg string) bool {
	tier1Prefixes := []string{
		"github.com/islishude/tss/internal/zk/paillier",
		"github.com/islishude/tss/internal/mta",
		"github.com/islishude/tss/internal/paillier",
	}
	for _, prefix := range tier1Prefixes {
		if strings.Contains(pkg, prefix) {
			return true
		}
	}
	return false
}

func tierBudget(tier string) (time.Duration, bool) {
	switch tier {
	case "tier0":
		return tier0Budget, true
	case "tier1":
		return tier1Budget, true
	case "integration":
		return integrationBudget, true
	default:
		return 0, false
	}
}

func collectRecords(r io.Reader, forceTier string) ([]testRecord, error) {
	scanner := bufio.NewScanner(r)
	var records []testRecord
	for scanner.Scan() {
		var ev testEvent
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			continue
		}
		if ev.Action != "pass" && ev.Action != "fail" {
			continue
		}
		if ev.Test == "" {
			continue
		}

		var tier string
		var budget time.Duration
		var hasBudget bool
		if forceTier != "" {
			tier = forceTier
			budget, hasBudget = tierBudget(forceTier)
		} else {
			tier, budget, hasBudget = tierForPackage(ev.Package)
		}
		if !hasBudget {
			continue
		}
		elapsed := time.Duration(ev.Elapsed * float64(time.Second))
		records = append(records, testRecord{
			Package: ev.Package,
			Test:    ev.Test,
			Tier:    tier,
			Budget:  budget,
			Elapsed: elapsed,
			Violate: elapsed > budget,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

func printViolations(w io.Writer, records []testRecord) int {
	var violations int
	for _, record := range records {
		if !record.Violate {
			continue
		}
		_, _ = fmt.Fprintf(w,
			"BUDGET VIOLATION: %s/%s took %v (budget %s, tier=%s)\n",
			record.Package, record.Test, record.Elapsed.Truncate(time.Millisecond), formatDuration(record.Budget), record.Tier)
		violations++
	}
	return violations
}

func topRecords(records []testRecord, topN int, leavesOnly bool) []testRecord {
	if leavesOnly {
		records = leafRecords(records)
	} else {
		records = append([]testRecord(nil), records...)
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].Elapsed != records[j].Elapsed {
			return records[i].Elapsed > records[j].Elapsed
		}
		if records[i].Package != records[j].Package {
			return records[i].Package < records[j].Package
		}
		return records[i].Test < records[j].Test
	})
	if topN > len(records) {
		topN = len(records)
	}
	return records[:topN]
}

func leafRecords(records []testRecord) []testRecord {
	testsByPackage := make(map[string][]string)
	for _, record := range records {
		testsByPackage[record.Package] = append(testsByPackage[record.Package], record.Test)
	}
	leaves := make([]testRecord, 0, len(records))
	for _, record := range records {
		childPrefix := record.Test + "/"
		hasChild := false
		for _, test := range testsByPackage[record.Package] {
			if strings.HasPrefix(test, childPrefix) {
				hasChild = true
				break
			}
		}
		if !hasChild {
			leaves = append(leaves, record)
		}
	}
	return leaves
}

func printTopRecords(w io.Writer, records []testRecord) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "ELAPSED\tBUDGET\tTIER\tPACKAGE\tTEST")
	for _, record := range records {
		_, _ = fmt.Fprintf(tw, "%v\t%v\t%s\t%s\t%s\n",
			record.Elapsed.Truncate(time.Millisecond),
			formatDuration(record.Budget),
			record.Tier,
			record.Package,
			record.Test)
	}
	_ = tw.Flush()
}

func formatDuration(d time.Duration) string {
	if d%time.Second == 0 {
		return fmt.Sprintf("%ds", int64(d/time.Second))
	}
	return d.String()
}

func parseOptions(args []string, stderr io.Writer) (options, int) {
	opts := options{failOnViolation: true}
	fs := flag.NewFlagSet("testbudget", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.IntVar(&opts.topN, "top", 0, "print top N slowest tests")
	fs.StringVar(&opts.forceTier, "tier", "", "force tier for all input events: tier0, tier1, integration")
	fs.BoolVar(&opts.leavesOnly, "leaves", false, "print only leaf subtests in top output")
	fs.BoolVar(&opts.failOnViolation, "fail", true, "exit non-zero on budget violations")
	if err := fs.Parse(args); err != nil {
		return opts, 2
	}
	if opts.topN < 0 {
		_, _ = fmt.Fprintf(stderr, "ERROR: -top must be >= 0\n")
		return opts, 2
	}
	if opts.forceTier != "" {
		if _, ok := tierBudget(opts.forceTier); !ok {
			_, _ = fmt.Fprintf(stderr, "ERROR: unsupported -tier %q; expected tier0, tier1, or integration\n", opts.forceTier)
			return opts, 2
		}
	}
	return opts, 0
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	opts, code := parseOptions(args, stderr)
	if code != 0 {
		return code
	}

	records, err := collectRecords(stdin, opts.forceTier)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "ERROR: reading input: %v\n", err)
		return 2
	}

	violations := printViolations(stderr, records)
	if opts.topN > 0 {
		printTopRecords(stdout, topRecords(records, opts.topN, opts.leavesOnly))
	}
	if violations > 0 {
		_, _ = fmt.Fprintf(stderr, "ERROR: %d test(s) exceeded their tier budget\n", violations)
		if opts.failOnViolation {
			return 1
		}
	}
	return 0
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
