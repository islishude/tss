package secp256k1

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/wire/wireutil"
)

// ExampleVerifyDigest demonstrates standalone ECDSA signature verification
// against a raw SHA-256 digest. This operates on single-party ECDSA keys
// without any threshold logic and is useful for verifying signatures produced
// by a completed threshold signing session.
//
// For threshold verification (including signer set and context binding),
// use [VerifySignature] instead.
func ExampleVerifyDigest() {
	// --- 1. Compute a SHA-256 digest to sign ---
	digest := sha256.Sum256([]byte("hello secp256k1"))

	// --- 2. Generate a single-party secp256k1 key ---
	secret, err := secp.RandomScalar(rand.Reader)
	if err != nil {
		panic(err)
	}

	// --- 3. Produce an ECDSA signature (r, s) ---
	r, s, err := secp.SignECDSA(rand.Reader, digest[:], secret, true)
	if err != nil {
		panic(err)
	}

	// --- 4. Derive the public key from the secret scalar ---
	publicKey, err := secp.PointBytes(secp.ScalarBaseMult(secret))
	if err != nil {
		panic(err)
	}

	// --- 5. Verify with the threshold-aware verifier ---
	// VerifyDigest checks the signature against the given public key and
	// digest without any threshold context (signer set, derivation path).
	signature := &Signature{R: r.Bytes(), S: s.Bytes()}
	fmt.Println(VerifyDigest(publicKey, digest[:], signature))
	// Output:
	// true
}

// ExampleVerifyBlameEvidence demonstrates how to verify blame evidence
// produced during a CGGMP21 protocol run. The verifier uses [EvidenceContext]
// to bind the evidence to the expected session parameters.
func ExampleVerifyBlameEvidence() {
	// --- 1. Create a session ID for the evidence context ---
	sessionID, err := tss.NewSessionID(bytes.NewReader(bytes.Repeat([]byte{0x44}, 32)))
	if err != nil {
		panic(err)
	}

	// --- 2. Build an envelope that represents the disputed message ---
	envelope := tss.Envelope{
		Protocol:    protocol,
		Version:     tss.Version,
		SessionID:   sessionID,
		Round:       1,
		From:        1,
		PayloadType: payloadSignPartial,
		Payload:     []byte("bad sign partial"),
	}

	// --- 3. Construct blame evidence with protocol-specific fields ---
	// partySetHashLabel and evidence field keys are protocol-internal
	// constants that bind the evidence to the expected party configuration.
	evidence, err := tss.NewBlameEvidence(
		envelope,
		tss.EvidenceKindSignPartial,
		"invalid sign partial signature",
		[]tss.EvidenceField{
			{Key: evidenceFieldPartiesHash, Value: wireutil.PartySetHash([]tss.PartyID{1}, partySetHashLabel)},
			{Key: evidenceFieldSignerSetHash, Value: wireutil.PartySetHash([]tss.PartyID{1}, partySetHashLabel)},
		},
	)
	if err != nil {
		panic(err)
	}

	// --- 4. Encode the evidence for transmission ---
	encoded, err := evidence.MarshalBinary()
	if err != nil {
		panic(err)
	}

	// --- 5. Verify with the expected session context ---
	// EvidenceContext carries the session parameters the verifier expects.
	// VerifyBlameEvidence cross-checks these against the embedded evidence
	// fields and validates structural integrity.
	err = VerifyBlameEvidence(encoded, EvidenceContext{
		SessionID: sessionID,
		Parties:   []tss.PartyID{1},
		Signers:   []tss.PartyID{1},
	})
	fmt.Println(err == nil)
	// Output:
	// true
}
