package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestSelectTargetsByKindAndName(t *testing.T) {
	wireTargets, err := selectTargets(opVerify, "wire")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(wireTargets), 6; got != want {
		t.Fatalf("wire target count = %d, want %d", got, want)
	}
	if wireTargets[0].Name != "wire/envelope" {
		t.Fatalf("first wire target = %q", wireTargets[0].Name)
	}

	fixtures, err := selectTargets(opUpdate, "fixtures/cggmp21-keygen")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(fixtures), 1; got != want {
		t.Fatalf("fixture target count = %d, want %d", got, want)
	}
	if fixtures[0].Outputs[0] != "fixtures/cggmp21-secp256k1/keygen_fixtures.json" {
		t.Fatalf("fixture output path = %q", fixtures[0].Outputs[0])
	}
}

func TestSelectTargetsRejectsUnknownSelector(t *testing.T) {
	if _, err := selectTargets(opVerify, "missing"); err == nil {
		t.Fatal("unknown selector succeeded")
	}
}

func TestIndependentEd25519BIP32VectorsAreVerifyOnly(t *testing.T) {
	const name = "protocol/ed25519-bip32"

	targets, err := selectTargets(opVerify, name)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0].Name != name {
		t.Fatalf("verify targets = %#v, want only %s", targets, name)
	}
	if _, err := selectTargets(opUpdate, name); err == nil {
		t.Fatal("independent Ed25519-BIP32 vector unexpectedly has an update target")
	}
}

func TestGoTestArgs(t *testing.T) {
	spec := runSpec{Run: "^TestGenerateVectors$", Tags: []string{"vectorgen"}}
	got := goTestArgs(spec, "45m", []string{"./frost/ed25519"})
	want := []string{"test", "-run", "^TestGenerateVectors$", "-tags", "vectorgen", "-count=1", "-timeout", "45m", "./frost/ed25519"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args = %#v, want %#v", got, want)
	}
}

func TestFormatTargetLineIncludesSafetyNotes(t *testing.T) {
	line := formatTargetLine(target{
		Name:        "fixtures/cggmp21-keygen",
		Kind:        "fixtures",
		Tier:        "2",
		Outputs:     []string{"fixtures/cggmp21-secp256k1/keygen_fixtures.json"},
		Secret:      true,
		Description: "committed test-only private shares",
	})
	for _, want := range []string{
		"fixtures/cggmp21-keygen",
		"Tier 2",
		"fixtures",
		"1 file",
		"contains test secret material",
		"committed test-only private shares",
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("line %q missing %q", line, want)
		}
	}
}

func TestCommandEnvScrubsGenerationControls(t *testing.T) {
	t.Setenv("UPDATE_GOLDEN", "1")
	t.Setenv("GENERATE_VECTORS", "1")
	env := commandEnv(nil)
	for _, kv := range env {
		if strings.HasPrefix(kv, "UPDATE_GOLDEN=") || strings.HasPrefix(kv, "GENERATE_VECTORS=") {
			t.Fatalf("verify env leaked generation control: %q", kv)
		}
	}

	env = commandEnv(map[string]string{"UPDATE_GOLDEN": "1"})
	found := false
	for _, kv := range env {
		if kv == "UPDATE_GOLDEN=1" {
			found = true
		}
		if kv == "GENERATE_VECTORS=1" {
			t.Fatalf("env leaked removed generator control: %q", kv)
		}
	}
	if !found {
		t.Fatal("update env missing UPDATE_GOLDEN=1")
	}
}
