// testbudget parses `go test -json` output from stdin and flags individual
// tests that exceed their tier's runtime budget. Budgets are defined in
// docs/testing-rules.md:
//
//	Tier 0: 500ms    Tier 1: 5s    Integration: 60s
//
// Usage:
//
//	go test -json ./... | go run ./internal/testutil/cmd/testbudget
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
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

// tierForPackage maps a package path to a tier label and budget. Returns
// ("", 0, false) for packages that have no budget enforcement.
func tierForPackage(pkg string) (string, time.Duration, bool) {
	switch {
	case strings.Contains(pkg, "slowcrypto"):
		return "slowcrypto", 0, false
	case strings.Contains(pkg, "securekey") || strings.Contains(pkg, "integration"):
		return "integration", integrationBudget, true
	case isTier1Package(pkg):
		return "tier1", tier1Budget, true
	default:
		return "tier0", tier0Budget, true
	}
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

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	var violations int

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

		tier, budget, hasBudget := tierForPackage(ev.Package)
		if !hasBudget {
			continue
		}

		elapsed := time.Duration(ev.Elapsed * float64(time.Second))
		if elapsed > budget {
			fmt.Fprintf(os.Stderr,
				"BUDGET VIOLATION: %s/%s took %v (budget %v, tier=%s)\n",
				ev.Package, ev.Test, elapsed.Truncate(time.Millisecond), budget, tier)
			violations++
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: reading input: %v\n", err)
		os.Exit(2)
	}

	if violations > 0 {
		fmt.Fprintf(os.Stderr, "ERROR: %d test(s) exceeded their tier budget\n", violations)
		os.Exit(1)
	}
}
