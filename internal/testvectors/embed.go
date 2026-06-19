package testvectors

import (
	"embed"
	"io/fs"
	"testing"
)

// Files contains the committed test vectors used for verification.
//
//go:embed wire protocol fixtures
var Files embed.FS

// Read reads a committed test vector from internal/testvectors.
func Read(tb testing.TB, name string) []byte {
	tb.Helper()

	data, err := ReadFile(name)
	if err != nil {
		tb.Fatalf("read test vector %s: %v", name, err)
	}
	return data
}

// ReadFile reads a committed test vector from internal/testvectors.
func ReadFile(name string) ([]byte, error) {
	clean, err := cleanName(name)
	if err != nil {
		return nil, err
	}
	data, err := fs.ReadFile(Files, clean)
	if err != nil {
		return nil, err
	}
	return data, nil
}
