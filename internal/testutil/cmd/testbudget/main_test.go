package main

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func TestRunDefaultReportsViolationsAndFails(t *testing.T) {
	input := `{"Action":"pass","Package":"github.com/islishude/tss/example","Test":"TestSlow","Elapsed":0.75}` + "\n"

	code, stdout, stderr := runTestbudget(t, nil, input)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stderr:\n%s", code, stderr)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	want := "BUDGET VIOLATION: github.com/islishude/tss/example/TestSlow took 750ms (budget 500ms, tier=tier0)"
	if !strings.Contains(stderr, want) {
		t.Fatalf("stderr missing violation %q:\n%s", want, stderr)
	}
	if !strings.Contains(stderr, "ERROR: 1 test(s) exceeded their tier budget") {
		t.Fatalf("stderr missing summary:\n%s", stderr)
	}
}

func TestRunFailFalseKeepsViolationOutputButExitsZero(t *testing.T) {
	input := `{"Action":"pass","Package":"github.com/islishude/tss/example","Test":"TestSlow","Elapsed":0.75}` + "\n"

	code, _, stderr := runTestbudget(t, []string{"-fail=false"}, input)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr:\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "BUDGET VIOLATION:") {
		t.Fatalf("stderr missing violation:\n%s", stderr)
	}
}

func TestRunTopPrintsSlowestLeafRecords(t *testing.T) {
	pkg := "github.com/islishude/tss/cggmp21/secp256k1"
	input := strings.Join([]string{
		`{"Action":"pass","Package":"` + pkg + `","Test":"TestFlow","Elapsed":42.318}`,
		`{"Action":"pass","Package":"` + pkg + `","Test":"TestFlow/child","Elapsed":18.204}`,
		`{"Action":"pass","Package":"` + pkg + `","Test":"TestOther","Elapsed":7}`,
		`{"Action":"pass","Package":"` + pkg + `","Test":"TestTiny","Elapsed":0.1}`,
		"",
	}, "\n")

	code, stdout, stderr := runTestbudget(t, []string{"-tier=integration", "-top=2", "-leaves", "-fail=false"}, input)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr:\n%s", code, stderr)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
	gotTests := topOutputTests(t, stdout)
	wantTests := []string{"TestFlow/child", "TestOther"}
	if !reflect.DeepEqual(gotTests, wantTests) {
		t.Fatalf("top tests = %#v, want %#v; stdout:\n%s", gotTests, wantTests, stdout)
	}
	if !strings.Contains(stdout, "18.204s") || !strings.Contains(stdout, "60s") || !strings.Contains(stdout, "integration") {
		t.Fatalf("stdout missing expected elapsed, budget, or tier:\n%s", stdout)
	}
}

func TestRunTierOverrideUsesForcedBudget(t *testing.T) {
	input := `{"Action":"pass","Package":"github.com/islishude/tss/example","Test":"TestWouldBeTier0Slow","Elapsed":1}` + "\n"

	code, stdout, stderr := runTestbudget(t, []string{"-tier=integration"}, input)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr:\n%s", code, stderr)
	}
	if stdout != "" || stderr != "" {
		t.Fatalf("stdout = %q, stderr = %q; want both empty", stdout, stderr)
	}
}

func TestRunRejectsUnsupportedTier(t *testing.T) {
	code, _, stderr := runTestbudget(t, []string{"-tier=slowcrypto"}, "")
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr, `unsupported -tier "slowcrypto"`) {
		t.Fatalf("stderr missing unsupported tier message:\n%s", stderr)
	}
}

func TestTierForPackageMapsProtocolIntegrationPackages(t *testing.T) {
	tests := []string{
		"github.com/islishude/tss/cggmp21/secp256k1",
		"github.com/islishude/tss/frost/ed25519",
	}
	for _, pkg := range tests {
		tier, budget, ok := tierForPackage(pkg)
		if !ok {
			t.Fatalf("tierForPackage(%q) returned no budget", pkg)
		}
		if tier != "integration" || budget != integrationBudget {
			t.Fatalf("tierForPackage(%q) = (%q, %v), want (integration, %v)", pkg, tier, budget, integrationBudget)
		}
	}
}

func runTestbudget(t *testing.T, args []string, input string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(args, strings.NewReader(input), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func topOutputTests(t *testing.T, output string) []string {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) == 0 || !strings.Contains(lines[0], "ELAPSED") {
		t.Fatalf("missing top output header:\n%s", output)
	}
	tests := make([]string, 0, len(lines)-1)
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) != 5 {
			t.Fatalf("top output row has %d fields, want 5: %q\nfull output:\n%s", len(fields), line, output)
		}
		tests = append(tests, fields[4])
	}
	return tests
}
