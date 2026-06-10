package tss

import (
	"bytes"
	"fmt"
)

// ExampleNewSessionID demonstrates how to generate a unique session identifier
// from a cryptographic random source. A nil reader uses crypto/rand.Reader.
// Session IDs are used to bind all messages in a protocol run together,
// preventing cross-session replay attacks.
func ExampleNewSessionID() {
	sessionID, err := NewSessionID(bytes.NewReader(bytes.Repeat([]byte{0x11}, 32)))
	if err != nil {
		panic(err)
	}

	fmt.Println(sessionID.String())
	// Output:
	// 1111111111111111111111111111111111111111111111111111111111111111
}

// ExampleEnvelope_roundtrip demonstrates the full lifecycle of an Envelope:
// construction via NewEnvelope, binary encoding, decoding, and validation.
// Envelopes carry protocol messages between parties; each envelope identifies
// the protocol, session, round, sender, and recipient for routing and
// duplicate detection.
func ExampleEnvelope_roundtrip() {
	// --- 1. Create a session ID that binds all messages in this run ---
	sessionID, err := NewSessionID(nil)
	if err != nil {
		panic(err)
	}

	// --- 2. Construct an envelope with the NewEnvelope constructor ---
	// NewEnvelope validates fields, computes the transcript hash, and
	// returns a ready-to-send envelope. Always prefer NewEnvelope over
	// constructing the struct directly.
	envelope, err := NewEnvelope(EnvelopeInput{
		Protocol:    "example",
		Version:     Version,
		SessionID:   sessionID,
		Round:       1,
		From:        1,
		PayloadType: "example.payload",
		Payload:     []byte("roundtrip test"),
	})
	if err != nil {
		panic(err)
	}

	// --- 3. Serialize the envelope for transport ---
	encoded, err := envelope.MarshalBinary()
	if err != nil {
		panic(err)
	}

	// --- 4. Deserialize on the receiving side ---
	var decoded Envelope
	if err := decoded.UnmarshalBinary(encoded); err != nil {
		panic(err)
	}

	// --- 5. Recompute the domain-separated transcript hash ---
	// The transcript hash commits to the full message chain. After
	// deserialization, copy it into the envelope so validation can
	// compare it against the expected chain state.
	copy(decoded.TranscriptHash[:], decoded.DomainSeparatedHash())

	// --- 6. Validate the decoded envelope ---
	// ValidateEnvelopeBasic checks protocol ID, session ID, round, and
	// sender membership in the expected party set. It does NOT verify
	// the EnvelopeGuard policies — use a guard for that.
	if err := ValidateEnvelopeBasic(decoded, "example", sessionID, []PartyID{1}); err != nil {
		panic(err)
	}

	fmt.Println(string(decoded.Payload))
	// Output:
	// roundtrip test
}

// ExampleBlameEvidence_lifecycle demonstrates the full blame evidence
// lifecycle: creation from a misbehaving envelope, binary encoding,
// decoding via UnmarshalBlameEvidence, and self-validation.
//
// Blame evidence captures the evidence needed to attribute a protocol
// fault to a specific party. It is designed to be stored or transmitted
// for later dispute resolution.
func ExampleBlameEvidence_lifecycle() {
	sessionID, err := NewSessionID(bytes.NewReader(bytes.Repeat([]byte{0x33}, 32)))
	if err != nil {
		panic(err)
	}

	// --- 1. Construct the envelope that triggered the fault ---
	envelope := Envelope{
		Protocol:    "example",
		Version:     Version,
		SessionID:   sessionID,
		Round:       1,
		From:        1,
		PayloadType: "example.payload",
		Payload:     []byte("bad partial"),
	}

	// --- 2. Create blame evidence binding the envelope to a fault ---
	// EvidenceKind describes the protocol phase where the fault occurred.
	// EvidenceFields carry structured key-value metadata (e.g., hashes,
	// party sets) that verifiers can cross-check.
	evidence, err := NewBlameEvidence(
		envelope,
		EvidenceKindSignPartial,
		"invalid partial signature",
		[]EvidenceField{
			{Key: "public_hash", Value: []byte{1, 2, 3}},
		},
	)
	if err != nil {
		panic(err)
	}

	// --- 3. Serialize blame evidence for storage or transmission ---
	encoded, err := evidence.MarshalBinary()
	if err != nil {
		panic(err)
	}

	// --- 4. Deserialize using the typed unmarshaler ---
	// UnmarshalBlameEvidence returns a *BlameEvidence (not a raw struct)
	// so the Validate method is available on the decoded value.
	decoded, err := UnmarshalBlameEvidence(encoded)
	if err != nil {
		panic(err)
	}

	// --- 5. Validate structural integrity ---
	// Validate checks that Kind is a known evidence kind and that From is
	// non-zero. Additional context-dependent checks (session ID, party
	// membership) are performed by protocol-specific verifiers.
	fmt.Println(decoded.Kind, decoded.From, decoded.Validate() == nil)
	// Output:
	// sign_partial 1 true
}

// ExampleStorage_encryptDecrypt demonstrates password-based encryption and
// decryption of key material using the reference EncryptKeyShareWithPassphrase
// and DecryptKeyShareWithPassphrase helpers. These functions are intended for
// local storage encryption at rest; they are NOT a substitute for transport
// encryption between parties.
func Example_encryptDecrypt() {
	passphrase := []byte("correct horse battery staple")
	keyMaterial := []byte("this is a serialized key share")

	// --- 1. Encrypt key material with a passphrase ---
	// The optional PassphraseParams can tune scrypt cost parameters.
	// A nil params uses production defaults (N=32768, r=8, p=1).
	encrypted, err := EncryptKeyShareWithPassphrase(keyMaterial, passphrase, "my-key-id", nil)
	if err != nil {
		panic(err)
	}

	// --- 2. Decrypt the ciphertext with the same passphrase ---
	// DecryptKeyShareWithPassphrase verifies the key ID and AEAD tag,
	// returning the original plaintext only if both are correct.
	decrypted, err := DecryptKeyShareWithPassphrase(encrypted, passphrase)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(decrypted))
	// Output:
	// this is a serialized key share
}
