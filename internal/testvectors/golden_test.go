package testvectors

import (
	"os"
	"strings"
	"testing"
)

func TestPathLocatesRepositoryTestVectors(t *testing.T) {
	p, err := Path("README.md")
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("stat README through testvectors.Path: %v", err)
	}
	if !strings.HasSuffix(p, "internal/testvectors/README.md") {
		t.Fatalf("Path returned unexpected location: %s", p)
	}
}

func TestReadUsesEmbeddedVectors(t *testing.T) {
	data := Read(t, "wire/v1/envelope/Envelope.golden")
	if len(data) == 0 {
		t.Fatal("embedded golden vector is empty")
	}
}

func TestFormatGoldenMismatchDoesNotExposeRawHex(t *testing.T) {
	got := []byte{0xde, 0xad, 0xbe, 0xef}
	want := []byte{0xba, 0xad, 0xf0, 0x0d}

	msg := formatGoldenMismatch("wire/v1/example.golden", got, want)
	for _, secretHex := range []string{"deadbeef", "baadf00d"} {
		if strings.Contains(msg, secretHex) {
			t.Fatalf("mismatch message leaked raw hex %q: %s", secretHex, msg)
		}
	}
	for _, required := range []string{
		"golden mismatch: wire/v1/example.golden",
		"got: 4 bytes",
		"want: 4 bytes",
		"got_sha256:",
		"want_sha256:",
		"make vectors-update-wire",
	} {
		if !strings.Contains(msg, required) {
			t.Fatalf("mismatch message missing %q: %s", required, msg)
		}
	}
}

func TestCleanNameRejectsInvalidPaths(t *testing.T) {
	for _, name := range []string{
		"",
		".",
		"./wire/v1/envelope/Envelope.golden",
		"../wire/v1/envelope/Envelope.golden",
		"wire/../README.md",
		"wire/.hidden",
		"/wire/v1/envelope/Envelope.golden",
		`wire\v1\envelope\Envelope.golden`,
		"C:/wire/v1/envelope/Envelope.golden",
	} {
		if _, err := cleanName(name); err == nil {
			t.Fatalf("cleanName(%q) succeeded", name)
		}
	}
}
