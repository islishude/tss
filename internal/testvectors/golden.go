package testvectors

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

const updateWireHint = "make vectors-update-wire"

// UpdateEnabled reports whether golden-vector update mode is enabled.
func UpdateEnabled() bool {
	return os.Getenv("UPDATE_GOLDEN") == "1"
}

// CheckHexGolden compares raw bytes against a committed hex-encoded golden
// vector under internal/testvectors. The rel argument is relative to
// internal/testvectors, for example "wire/v1/frost/KeyShare.golden".
func CheckHexGolden(tb testing.TB, rel string, raw []byte) {
	tb.Helper()

	clean, err := cleanName(rel)
	if err != nil {
		tb.Fatal(err)
	}

	if UpdateEnabled() {
		golden, err := Path(clean)
		if err != nil {
			tb.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(golden), 0o700); err != nil {
			tb.Fatal(err)
			return
		}
		if err := os.WriteFile(golden, []byte(hex.EncodeToString(raw)+"\n"), 0o600); err != nil {
			tb.Fatal(err)
		}
		return
	}

	wantHex := Read(tb, clean)
	wantTrimmed := bytes.TrimSpace(wantHex)
	wantRaw, err := hex.DecodeString(string(wantTrimmed))
	if err != nil {
		tb.Fatalf("golden %s contains invalid hex: %v (run: %s)", clean, err, updateWireHint)
		return
	}
	if canonical := hex.EncodeToString(wantRaw); canonical != string(wantTrimmed) {
		tb.Fatalf("golden %s is not canonical lowercase hex (run: %s)", clean, updateWireHint)
		return
	}
	if !bytes.Equal(raw, wantRaw) {
		tb.Fatal(formatGoldenMismatch(clean, raw, wantRaw))
	}
}

func formatGoldenMismatch(rel string, got, want []byte) string {
	gotHash := sha256.Sum256(got)
	wantHash := sha256.Sum256(want)
	return fmt.Sprintf(
		"golden mismatch: %s\n  got: %d bytes\n  want: %d bytes\n  got_sha256: %x\n  want_sha256: %x\n  run: %s",
		rel,
		len(got),
		len(want),
		gotHash,
		wantHash,
		updateWireHint,
	)
}
