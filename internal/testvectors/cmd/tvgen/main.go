package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
)

const defaultTimeout = "30m"

type operation string

const (
	opUpdate operation = "update"
	opVerify operation = "verify"
)

type runSpec struct {
	Run  string
	Tags []string
	Env  map[string]string
}

type target struct {
	Name        string
	Kind        string
	Tier        string
	Packages    []string
	Update      runSpec
	Verify      runSpec
	Outputs     []string
	Secret      bool
	Description string
}

type config struct {
	timeout string
	goBin   string
	stdout  *os.File
	stderr  *os.File
}

func main() {
	if err := run(os.Args[1:], config{
		timeout: defaultTimeout,
		goBin:   goBinary(),
		stdout:  os.Stdout,
		stderr:  os.Stderr,
	}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, cfg config) error {
	fs := flag.NewFlagSet("tvgen", flag.ContinueOnError)
	fs.SetOutput(cfg.stderr)
	fs.StringVar(&cfg.timeout, "timeout", cfg.timeout, "go test timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) == 0 {
		return usageError("missing command")
	}

	switch rest[0] {
	case "list":
		if len(rest) != 1 {
			return usageError("list does not accept a target")
		}
		return listTargets(cfg.stdout)
	case string(opUpdate), string(opVerify):
		if len(rest) != 2 {
			return usageError(fmt.Sprintf("%s requires one target selector", rest[0]))
		}
		return runTargets(operation(rest[0]), rest[1], cfg)
	default:
		return usageError(fmt.Sprintf("unknown command %q", rest[0]))
	}
}

func usageError(msg string) error {
	return fmt.Errorf("%s\nusage:\n  tvgen [-timeout 30m] list\n  tvgen [-timeout 30m] update [all|wire|protocol|fixtures|target]\n  tvgen [-timeout 30m] verify [all|wire|protocol|fixtures|target]", msg)
}

func goBinary() string {
	if goBin := os.Getenv("GO"); goBin != "" {
		return goBin
	}
	return "go"
}

func listTargets(out *os.File) error {
	for _, t := range manifest {
		if _, err := fmt.Fprintln(out, formatTargetLine(t)); err != nil {
			return fmt.Errorf("write target list: %w", err)
		}
	}
	return nil
}

func formatTargetLine(t target) string {
	notes := make([]string, 0, 3)
	if t.Secret {
		notes = append(notes, "contains test secret material")
	}
	if t.Description != "" {
		notes = append(notes, t.Description)
	}
	line := fmt.Sprintf("%-32s %-8s %-7s %2d %s", t.Name, "Tier "+t.Tier, t.Kind, len(t.Outputs), plural("file", len(t.Outputs)))
	if len(notes) > 0 {
		line += "  " + strings.Join(notes, "; ")
	}
	return line
}

func plural(word string, n int) string {
	if n == 1 {
		return word
	}
	return word + "s"
}

func runTargets(op operation, selector string, cfg config) error {
	targets, err := selectTargets(op, selector)
	if err != nil {
		return err
	}
	for _, t := range targets {
		spec, ok := specForOperation(t, op)
		if !ok {
			return fmt.Errorf("target %s does not support %s", t.Name, op)
		}
		if err := runGoTest(t, spec, cfg); err != nil {
			return err
		}
	}
	return nil
}

func selectTargets(op operation, selector string) ([]target, error) {
	if selector == "" {
		return nil, errors.New("empty target selector")
	}
	var out []target
	for _, t := range manifest {
		if selector == "all" || selector == t.Kind || selector == t.Name {
			if _, ok := specForOperation(t, op); ok {
				out = append(out, t)
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no %s targets match %q", op, selector)
	}
	return out, nil
}

func specForOperation(t target, op operation) (runSpec, bool) {
	var spec runSpec
	switch op {
	case opUpdate:
		spec = t.Update
	case opVerify:
		spec = t.Verify
	default:
		return runSpec{}, false
	}
	if spec.Run == "" {
		return runSpec{}, false
	}
	return spec, true
}

func runGoTest(t target, spec runSpec, cfg config) error {
	args := goTestArgs(spec, cfg.timeout, t.Packages)
	cmd := exec.Command(cfg.goBin, args...) //nolint:gosec // command and args come from the static manifest
	cmd.Env = commandEnv(spec.Env)
	cmd.Stdout = cfg.stdout
	cmd.Stderr = cfg.stderr

	if _, err := fmt.Fprintf(cfg.stdout, "==> %s\n", t.Name); err != nil {
		return fmt.Errorf("write target header: %w", err)
	}
	if _, err := fmt.Fprintf(cfg.stdout, "$ %s\n", commandLine(cfg.goBin, args, spec.Env)); err != nil {
		return fmt.Errorf("write command line: %w", err)
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s failed: %w", t.Name, err)
	}
	return nil
}

func goTestArgs(spec runSpec, timeout string, packages []string) []string {
	args := []string{"test", "-run", spec.Run}
	if len(spec.Tags) > 0 {
		args = append(args, "-tags", strings.Join(spec.Tags, ","))
	}
	args = append(args, "-count=1", "-timeout", timeout)
	args = append(args, packages...)
	return args
}

func envList(env map[string]string) []string {
	if len(env) == 0 {
		return nil
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]string, 0, len(env))
	for _, k := range keys {
		out = append(out, k+"="+env[k])
	}
	return out
}

func commandEnv(env map[string]string) []string {
	blocked := map[string]struct{}{
		"GENERATE_VECTORS": {},
		"UPDATE_GOLDEN":    {},
	}
	for k := range env {
		blocked[k] = struct{}{}
	}

	out := make([]string, 0, len(os.Environ())+len(env))
	for _, kv := range os.Environ() {
		key, _, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		if _, drop := blocked[key]; drop {
			continue
		}
		out = append(out, kv)
	}
	out = append(out, envList(env)...)
	return out
}

func commandLine(goBin string, args []string, env map[string]string) string {
	parts := append(envList(env), goBin)
	parts = append(parts, args...)
	for i := range parts {
		parts[i] = shellQuote(parts[i])
	}
	return strings.Join(parts, " ")
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	if strings.IndexFunc(s, func(r rune) bool { return !safeShellChar(r) }) == -1 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

func safeShellChar(r rune) bool {
	switch {
	case r == '_' || r == '-' || r == '.' || r == '/' || r == '=':
		return true
	case r == ':' || r == '$' || r == '^' || r == '|' || r == ',':
		return true
	case r == '+' || r == '%' || r == '@' || r == '~':
		return true
	case r >= '0' && r <= '9':
		return true
	case r >= 'A' && r <= 'Z':
		return true
	case r >= 'a' && r <= 'z':
		return true
	default:
		return false
	}
}
