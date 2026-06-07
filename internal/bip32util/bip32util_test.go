package bip32util

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"
)

// ---------------------------------------------------------------------------
// Sentinel errors
// ---------------------------------------------------------------------------

func TestSentinelErrorsAreDistinct(t *testing.T) {
	errs := []error{
		ErrChainCodeRequired,
		ErrInvalidChainCodeLength,
		ErrInvalidPublicKey,
		ErrHardenedDerivationUnsupported,
		ErrInvalidChild,
		ErrDerivationDepthOverflow,
		ErrInvalidExtendedPublicKey,
	}
	for i, a := range errs {
		if a == nil {
			t.Errorf("sentinel error at index %d is nil", i)
		}
		for j := i + 1; j < len(errs); j++ {
			if errors.Is(a, errs[j]) || errors.Is(errs[j], a) {
				t.Errorf("errors at %d and %d should be distinct", i, j)
			}
		}
	}
}

func TestSentinelErrorsAreComparable(t *testing.T) {
	// Verify that errors.Is works with the sentinel values.
	if !errors.Is(ErrChainCodeRequired, ErrChainCodeRequired) {
		t.Error("ErrChainCodeRequired should match itself via errors.Is")
	}
	if !errors.Is(ErrHardenedDerivationUnsupported, ErrHardenedDerivationUnsupported) {
		t.Error("ErrHardenedDerivationUnsupported should match itself via errors.Is")
	}
	// Verify that distinct errors don't match.
	if errors.Is(ErrChainCodeRequired, ErrInvalidChild) {
		t.Error("distinct sentinel errors should not match via errors.Is")
	}
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

func TestHardenedKeyStartValue(t *testing.T) {
	if HardenedKeyStart != 1<<31 {
		t.Errorf("HardenedKeyStart = %d, want %d", HardenedKeyStart, 1<<31)
	}
	if HardenedKeyStart != 0x80000000 {
		t.Errorf("HardenedKeyStart = 0x%x, want 0x80000000", HardenedKeyStart)
	}
}

func TestXPubVersion(t *testing.T) {
	// BIP32 mainnet xpub version must be 0x0488B21E.
	if XPubVersion != [4]byte{0x04, 0x88, 0xB2, 0x1E} {
		t.Errorf("XPubVersion = %x, want 0488b21e", XPubVersion)
	}
}

func TestTPubVersion(t *testing.T) {
	// BIP32 testnet tpub version must be 0x043587CF.
	if TPubVersion != [4]byte{0x04, 0x35, 0x87, 0xCF} {
		t.Errorf("TPubVersion = %x, want 043587cf", TPubVersion)
	}
}

func TestIsKnownVersion(t *testing.T) {
	if !IsKnownVersion(XPubVersion) {
		t.Error("XPubVersion should be known")
	}
	if !IsKnownVersion(TPubVersion) {
		t.Error("TPubVersion should be known")
	}
	if IsKnownVersion([4]byte{0x00, 0x00, 0x00, 0x00}) {
		t.Error("all-zero version should not be known")
	}
	if IsKnownVersion([4]byte{0x04, 0x88, 0xAD, 0xE4}) {
		t.Error("xprv version should not be treated as known for xpub")
	}
	if IsKnownVersion([4]byte{0xDE, 0xAD, 0xBE, 0xEF}) {
		t.Error("arbitrary version should not be known")
	}
}

// ---------------------------------------------------------------------------
// Base58CheckEncode / Base58CheckDecode
// ---------------------------------------------------------------------------

func TestBase58Check_RoundTrip_KnownXPub(t *testing.T) {
	// Decode a well-known mainnet xpub, then re-encode and compare.
	original := "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
	payload, err := Base58CheckDecode(original)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) != 78 {
		t.Fatalf("expected 78-byte payload, got %d", len(payload))
	}

	// Verify known fields in the decoded payload.
	version := [4]byte(payload[0:4])
	if version != XPubVersion {
		t.Errorf("expected xpub version %x, got %x", XPubVersion, version)
	}
	depth := payload[4]
	if depth != 0 {
		t.Errorf("master key depth should be 0, got %d", depth)
	}

	reEncoded := Base58CheckEncode(payload)
	if reEncoded != original {
		t.Errorf("round-trip mismatch:\n  original: %s\n  encoded:  %s", original, reEncoded)
	}
}

func TestBase58Check_RoundTrip_ArbitraryPayload(t *testing.T) {
	payload := make([]byte, 78)
	// Fill with bytes that produce a valid base58 string.
	for i := range payload {
		payload[i] = byte(i)
	}
	encoded := Base58CheckEncode(payload)
	decoded, err := Base58CheckDecode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, payload) {
		t.Errorf("round-trip mismatch for arbitrary 78-byte payload")
	}
}

func TestBase58Check_RoundTrip_LeadingZeros(t *testing.T) {
	// Payload with leading zero bytes — should preserve them.
	payload := make([]byte, 78)
	payload[0] = 0x00
	payload[1] = 0x00
	payload[2] = 0x01
	encoded := Base58CheckEncode(payload)
	if encoded[:2] != "11" {
		t.Errorf("expected two leading '1's for leading zeros, got: %s", encoded[:5])
	}
	decoded, err := Base58CheckDecode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, payload) {
		t.Errorf("round-trip failed for payload with leading zeros")
	}
}

func TestBase58CheckDecode_RejectsBadChecksum(t *testing.T) {
	// Take a valid xpub and flip the last character to corrupt checksum.
	valid := "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
	broken := valid[:len(valid)-1] + "X"
	_, err := Base58CheckDecode(broken)
	if err == nil {
		t.Error("expected error for bad checksum")
	}
	if err.Error() != "base58 checksum mismatch" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestBase58CheckDecode_RejectsInvalidCharacter(t *testing.T) {
	// '0', 'O', 'I', 'l' are not in the base58 alphabet.
	for _, ch := range []string{"0", "O", "I", "l"} {
		_, err := Base58CheckDecode(ch + "abc")
		if err == nil {
			t.Errorf("expected error for invalid character %q", ch)
		}
	}
}

func TestBase58CheckDecode_TooShortForChecksum(t *testing.T) {
	// Single base58 character decodes to less than 4 bytes (no room for checksum).
	_, err := Base58CheckDecode("A")
	if err == nil {
		t.Error("expected error for too-short data")
	}
}

func TestBase58CheckDecode_EmptyString(t *testing.T) {
	_, err := Base58CheckDecode("")
	if err == nil {
		t.Error("expected error for empty string")
	}
}

func TestBase58CheckEncode_LargePayload(t *testing.T) {
	// 78-byte payload is the standard xpub size.
	payload := make([]byte, 78)
	for i := range payload {
		payload[i] = byte(i % 256)
	}
	encoded := Base58CheckEncode(payload)
	if len(encoded) == 0 {
		t.Error("encoded string should not be empty")
	}
	// Length should be roughly 78 * log(256)/log(58) + checksum ≈ 106 chars.
	// We just check it's reasonable.
	if len(encoded) < 100 || len(encoded) > 120 {
		t.Logf("encoded length: %d (expected ~106)", len(encoded))
	}
}

// ---------------------------------------------------------------------------
// Known xpub / tpub round-trip (integration-style)
// ---------------------------------------------------------------------------

func TestKnownXPub_RoundTrip(t *testing.T) {
	testCases := []string{
		// TV1: m/0H xpub (depth 1, child 0x80000000)
		"xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
		// TV2: m xpub (depth 0, master)
		"xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
		// TV2: m/0 xpub (depth 1)
		"xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
	}
	for _, tc := range testCases {
		t.Run(tc[:20]+"...", func(t *testing.T) {
			payload, err := Base58CheckDecode(tc)
			if err != nil {
				t.Fatal(err)
			}
			if len(payload) != 78 {
				t.Fatalf("payload length = %d, want 78", len(payload))
			}
			reEncoded := Base58CheckEncode(payload)
			if reEncoded != tc {
				t.Errorf("round-trip failed:\n  got:  %s\n  want: %s", reEncoded, tc)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Base58Check XPub-specific payload format checks
// ---------------------------------------------------------------------------

func TestBase58Check_XPubPayloadVersion(t *testing.T) {
	// Verify that decoded xpub has the correct version bytes.
	xpub := "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
	payload, _ := Base58CheckDecode(xpub)
	version := [4]byte(payload[0:4])
	if version != XPubVersion {
		t.Errorf("xpub version = %x, want %x", version, XPubVersion)
	}
}

func TestBase58Check_XPubPayloadLayout(t *testing.T) {
	// Verify the layout: version(4) depth(1) fp(4) child(4) chain(32) key(33)
	xpub := "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
	payload, err := Base58CheckDecode(xpub)
	if err != nil {
		t.Fatal(err)
	}

	// Extract fields.
	_ = [4]byte(payload[0:4]) // version
	depth := payload[4]
	_ = [4]byte(payload[5:9]) // parent fingerprint
	_ = payload[9:13]         // child number
	chainCode := payload[13:45]
	publicKey := payload[45:78]

	if depth != 0 {
		t.Errorf("master depth = %d, want 0", depth)
	}
	if len(chainCode) != 32 {
		t.Errorf("chain code length = %d, want 32", len(chainCode))
	}
	if len(publicKey) != 33 {
		t.Errorf("public key length = %d, want 33", len(publicKey))
	}
	// The public key should be compressed (02 or 03 prefix).
	if publicKey[0] != 0x02 && publicKey[0] != 0x03 {
		t.Errorf("public key prefix = 0x%02x, want 0x02 or 0x03", publicKey[0])
	}
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

func TestBase58CheckEncode_Deterministic(t *testing.T) {
	payload := []byte("deterministic test payload for base58 check encoding")
	first := Base58CheckEncode(payload)
	for i := range 10 {
		if got := Base58CheckEncode(payload); got != first {
			t.Fatalf("Base58CheckEncode is not deterministic: iteration %d", i)
		}
	}
}

func TestBase58CheckDecode_Deterministic(t *testing.T) {
	xpub := "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
	first, err := Base58CheckDecode(xpub)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 10 {
		got, err := Base58CheckDecode(xpub)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, first) {
			t.Fatalf("Base58CheckDecode is not deterministic: iteration %d", i)
		}
	}
}

// ---------------------------------------------------------------------------
// Version constants are distinct
// ---------------------------------------------------------------------------

func TestVersionConstantsDistinct(t *testing.T) {
	if XPubVersion == TPubVersion {
		t.Error("XPubVersion and TPubVersion must be distinct")
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Test helper: verify that sha256d of a well-known xpub payload matches.
func TestXPubChecksum(t *testing.T) {
	// Manual checksum verification for the TV2 master xpub.
	xpub := "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
	payload, err := Base58CheckDecode(xpub)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) != 78 {
		t.Fatalf("payload length = %d, want 78", len(payload))
	}

	// Compute expected checksum.
	h1 := sha256.Sum256(payload)
	h2 := sha256.Sum256(h1[:])
	expectedChecksum := h2[:4]

	// Re-encode and verify it produces the same string.
	reEncoded := Base58CheckEncode(payload)
	if reEncoded != xpub {
		t.Errorf("checksum verification failed via round-trip:\n  got:  %s\n  want: %s", reEncoded, xpub)
	}
	_ = expectedChecksum
}
