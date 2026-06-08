//go:build integration

package secp256k1

import (
	"errors"
	"testing"

	"github.com/islishude/tss"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/wire"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

// TestKeygenRejectsMissingModulusProof verifies that a keygen commitments
// message with a zeroed PaillierProof is rejected. Omitting Πmod would
// allow a party to register a Paillier key without proving knowledge of
// its factorization — a CVE-class vulnerability.
func TestKeygenRejectsMissingModulusProof(t *testing.T) {
	parties := []tss.PartyID{1, 2}
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}

	kg1, _, err := StartKeygen(tss.ThresholdConfig{Threshold: 2, Parties: parties, Self: 1, SessionID: sessionID})
	if err != nil {
		t.Fatal(err)
	}
	_, out2, err := StartKeygen(tss.ThresholdConfig{Threshold: 2, Parties: parties, Self: 2, SessionID: sessionID})
	if err != nil {
		t.Fatal(err)
	}

	// Replace the modulus proof with invalid bytes (not a valid TLV proof).
	// We must bypass marshalKeygenCommitmentsPayload because it validates
	// the proof during marshaling. Instead, we construct the wire encoding
	// directly with corrupted proof bytes.
	payload, err := unmarshalKeygenCommitmentsPayload(out2[0].Payload)
	if err != nil {
		t.Fatal(err)
	}
	corruptedProof := make([]byte, len(payload.PaillierProof))
	for i := range corruptedProof {
		corruptedProof[i] = payload.PaillierProof[i] ^ 0xFF
	}
	mutated, err := marshalKeygenCommitmentsPayloadBypass(payload, keygenCommitmentsOverrides{PaillierProof: corruptedProof})
	if err != nil {
		t.Fatal(err)
	}
	out2[0].Payload = mutated
	out2[0] = out2[0].RecomputeTranscriptHash()
	if _, err := kg1.HandleKeygenMessage(out2[0]); err == nil {
		t.Fatal("keygen accepted commitments message with corrupted modulus proof")
	}
}

// TestKeygenRejectsMissingRingPedersenProof verifies that a keygen
// commitments message with a zeroed RingPedersenProof is rejected.
// Omitting Πprm allows a party to use Ring-Pedersen parameters without
// proving knowledge of the discrete log relation with its Paillier key.
func TestKeygenRejectsMissingRingPedersenProof(t *testing.T) {
	parties := []tss.PartyID{1, 2}
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}

	kg1, _, err := StartKeygen(tss.ThresholdConfig{Threshold: 2, Parties: parties, Self: 1, SessionID: sessionID})
	if err != nil {
		t.Fatal(err)
	}
	_, out2, err := StartKeygen(tss.ThresholdConfig{Threshold: 2, Parties: parties, Self: 2, SessionID: sessionID})
	if err != nil {
		t.Fatal(err)
	}

	payload, err := unmarshalKeygenCommitmentsPayload(out2[0].Payload)
	if err != nil {
		t.Fatal(err)
	}
	corruptedRP := make([]byte, len(payload.RingPedersenProof))
	for i := range corruptedRP {
		corruptedRP[i] = payload.RingPedersenProof[i] ^ 0xFF
	}
	mutated, err := marshalKeygenCommitmentsPayloadBypass(payload, keygenCommitmentsOverrides{RingPedersenProof: corruptedRP})
	if err != nil {
		t.Fatal(err)
	}
	out2[0].Payload = mutated
	out2[0] = out2[0].RecomputeTranscriptHash()
	if _, err := kg1.HandleKeygenMessage(out2[0]); err == nil {
		t.Fatal("keygen accepted commitments message with corrupted Ring-Pedersen proof")
	}
}

// keygenCommitmentsOverrides allows selective field substitution when
// constructing a keygen commitments payload for adversarial tests.
// Nil fields keep the original payload value.
type keygenCommitmentsOverrides struct {
	PaillierPublicKey []byte
	PaillierProof     []byte
	RingPedersenProof []byte
}

// marshalKeygenCommitmentsPayloadBypass constructs a wire-encoded keygen
// commitments payload, applying the given overrides. Fields not overridden
// (nil in overrides struct) use the original payload value unchanged.
// This bypasses the proof/key validation in marshalKeygenCommitmentsPayload;
// it is used ONLY for tests that verify rejection of corrupted messages.
func marshalKeygenCommitmentsPayloadBypass(p keygenCommitmentsPayload, o keygenCommitmentsOverrides) ([]byte, error) {
	if err := validateCommitmentPoints(p.Commitments); err != nil {
		return nil, err
	}
	if len(p.ChainCodeCommit) != 0 && len(p.ChainCodeCommit) != 32 {
		return nil, errors.New("chain code must be 32 bytes")
	}
	// Apply overrides: use original value when override is nil.
	pkBytes := p.PaillierPublicKey
	if o.PaillierPublicKey != nil {
		pkBytes = o.PaillierPublicKey
	} else if _, err := pai.UnmarshalPublicKey(pkBytes); err != nil {
		return nil, err
	}
	modProof := p.PaillierProof
	if o.PaillierProof != nil {
		modProof = o.PaillierProof
	}
	rpProof := p.RingPedersenProof
	if o.RingPedersenProof != nil {
		rpProof = o.RingPedersenProof
	}
	if _, err := zkpai.UnmarshalRingPedersenParams(p.RingPedersenParams); err != nil {
		return nil, err
	}
	return wire.Marshal(tss.Version, keygenCommitmentsPayloadWireType, []wire.Field{
		{Tag: keygenCommitmentsPayloadFieldCommitments, Value: wire.EncodeBytesList(p.Commitments)},
		{Tag: keygenCommitmentsPayloadFieldPaillierPublicKey, Value: wire.NonNilBytes(pkBytes)},
		{Tag: keygenCommitmentsPayloadFieldPaillierProof, Value: wire.NonNilBytes(modProof)},
		{Tag: keygenCommitmentsPayloadFieldChainCode, Value: wire.NonNilBytes(p.ChainCodeCommit)},
		{Tag: keygenCommitmentsPayloadFieldRingPedersenParams, Value: wire.NonNilBytes(p.RingPedersenParams)},
		{Tag: keygenCommitmentsPayloadFieldRingPedersenProof, Value: wire.NonNilBytes(rpProof)},
	})
}

// TestKeygenRejectsInvalidModulusProof verifies that a keygen commitments
// message with a structurally valid but cryptographically wrong modulus proof
// is rejected.
func TestKeygenRejectsInvalidModulusProof(t *testing.T) {
	parties := []tss.PartyID{1, 2}
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}

	kg1, _, err := StartKeygen(tss.ThresholdConfig{Threshold: 2, Parties: parties, Self: 1, SessionID: sessionID})
	if err != nil {
		t.Fatal(err)
	}
	_, out2, err := StartKeygen(tss.ThresholdConfig{Threshold: 2, Parties: parties, Self: 2, SessionID: sessionID})
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with the proof bytes: flip a bit in the transcript hash.
	payload, err := unmarshalKeygenCommitmentsPayload(out2[0].Payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload.PaillierProof) > 0 {
		payload.PaillierProof[len(payload.PaillierProof)-1] ^= 1
	}
	mutated, err := marshalKeygenCommitmentsPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	out2[0].Payload = mutated
	out2[0] = out2[0].RecomputeTranscriptHash()
	if _, err := kg1.HandleKeygenMessage(out2[0]); err == nil {
		t.Fatal("keygen accepted commitments message with invalid modulus proof")
	}
}

// TestKeygenRejectsInvalidRingPedersenProof verifies that a keygen
// commitments message with an invalid Ring-Pedersen proof is rejected.
func TestKeygenRejectsInvalidRingPedersenProof(t *testing.T) {
	parties := []tss.PartyID{1, 2}
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}

	kg1, _, err := StartKeygen(tss.ThresholdConfig{Threshold: 2, Parties: parties, Self: 1, SessionID: sessionID})
	if err != nil {
		t.Fatal(err)
	}
	_, out2, err := StartKeygen(tss.ThresholdConfig{Threshold: 2, Parties: parties, Self: 2, SessionID: sessionID})
	if err != nil {
		t.Fatal(err)
	}

	payload, err := unmarshalKeygenCommitmentsPayload(out2[0].Payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload.RingPedersenProof) > 0 {
		payload.RingPedersenProof[len(payload.RingPedersenProof)-1] ^= 1
	}
	mutated, err := marshalKeygenCommitmentsPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	out2[0].Payload = mutated
	out2[0] = out2[0].RecomputeTranscriptHash()
	if _, err := kg1.HandleKeygenMessage(out2[0]); err == nil {
		t.Fatal("keygen accepted commitments message with invalid Ring-Pedersen proof")
	}
}

// TestKeyShareValidateRejectsMissingLogStarProof verifies that a KeyShare
// with an empty LogProof is rejected by Validate(). The LogStarProof is
// critical: it proves that the Paillier-encrypted share matches the
// public verification share. Without it, a malicious party could submit
// an unrelated ciphertext that decrypts to a different scalar, recovering
// the full private key share-by-share.
func TestKeyShareValidateRejectsMissingLogStarProof(t *testing.T) {
	shares := secpKeygen(t, 2, 2)
	share := shares[1]

	// Marshal/unmarshal to get a clean copy.
	raw, err := share.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalKeyShare(raw)
	if err != nil {
		t.Fatal(err)
	}

	// Remove the log proof.
	decoded.LogProof = nil
	_, err = decoded.MarshalBinary()
	if err == nil {
		t.Fatal("KeyShare with missing LogProof marshaled successfully")
	}
}

// TestKeyShareValidateRejectsInvalidLogStarProof verifies that a KeyShare
// with a tampered LogProof is rejected.
func TestKeyShareValidateRejectsInvalidLogStarProof(t *testing.T) {
	shares := secpKeygen(t, 2, 2)
	share := shares[1]

	raw, err := share.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalKeyShare(raw)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with the log proof bytes.
	if len(decoded.LogProof) > 0 {
		decoded.LogProof[len(decoded.LogProof)-1] ^= 1
	}
	_, err = decoded.MarshalBinary()
	if err == nil {
		t.Fatal("KeyShare with invalid LogProof marshaled successfully")
	}
}

// TestKeyShareValidateRejectsMissingSchnorrProof verifies that a KeyShare
// with an empty Schnorr share proof is rejected. Without the Schnorr proof,
// the verification share cannot be authenticated.
func TestKeyShareValidateRejectsMissingSchnorrProof(t *testing.T) {
	shares := secpKeygen(t, 2, 2)
	share := shares[1]

	raw, err := share.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalKeyShare(raw)
	if err != nil {
		t.Fatal(err)
	}

	decoded.ShareProof = nil
	_, err = decoded.MarshalBinary()
	if err == nil {
		t.Fatal("KeyShare with missing ShareProof marshaled successfully")
	}
}

// TestKeyShareValidateRejectsMissingPaillierProof verifies that a KeyShare
// without a PaillierProof cannot be marshaled (and thus cannot be persisted).
// The PaillierProof (Πmod) proves knowledge of the Paillier key factorization.
func TestKeyShareValidateRejectsMissingPaillierProof(t *testing.T) {
	shares := secpKeygen(t, 2, 2)
	share := shares[1]

	raw, err := share.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalKeyShare(raw)
	if err != nil {
		t.Fatal(err)
	}

	decoded.PaillierProof = nil
	_, err = decoded.MarshalBinary()
	if err == nil {
		t.Fatal("KeyShare with missing PaillierProof marshaled successfully")
	}
}

// TestKeyShareValidateRejectsMissingRingPedersenProof verifies that
// a KeyShare without a RingPedersenProof is rejected.
func TestKeyShareValidateRejectsMissingRingPedersenProof(t *testing.T) {
	shares := secpKeygen(t, 2, 2)
	share := shares[1]

	raw, err := share.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalKeyShare(raw)
	if err != nil {
		t.Fatal(err)
	}

	decoded.RingPedersenProof = nil
	_, err = decoded.MarshalBinary()
	if err == nil {
		t.Fatal("KeyShare with missing RingPedersenProof marshaled successfully")
	}
}

// TestKeygenRejectsCorruptedPaillierPublicKey verifies that a keygen
// commitments message with a structurally invalid Paillier public key
// is rejected. The pai.UnmarshalPublicKey call inside marshalKeygenCommitmentsPayload
// catches this before the message is even sent, and HandleKeygenMessage
// also validates it on receipt.
func TestKeygenRejectsCorruptedPaillierPublicKey(t *testing.T) {
	parties := []tss.PartyID{1, 2}
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}

	kg1, _, err := StartKeygen(tss.ThresholdConfig{Threshold: 2, Parties: parties, Self: 1, SessionID: sessionID})
	if err != nil {
		t.Fatal(err)
	}
	_, out2, err := StartKeygen(tss.ThresholdConfig{Threshold: 2, Parties: parties, Self: 2, SessionID: sessionID})
	if err != nil {
		t.Fatal(err)
	}

	// The Paillier public key is validated at multiple levels:
	// 1. marshalKeygenCommitmentsPayload calls pai.UnmarshalPublicKey
	// 2. HandleKeygenMessage calls pai.UnmarshalPublicKey again
	// A structurally invalid key (not valid TLV) is caught at level 1 (send-side)
	// or level 2 (receive-side). We verify the receive-side here.
	payload, err := unmarshalKeygenCommitmentsPayload(out2[0].Payload)
	if err != nil {
		t.Fatal(err)
	}
	// Use a bypass that skips key validation but still produces valid wire format.
	corruptedKey := make([]byte, len(payload.PaillierPublicKey))
	for i := range corruptedKey {
		corruptedKey[i] = payload.PaillierPublicKey[i] ^ 0xFF
	}
	mutated, err := marshalKeygenCommitmentsPayloadBypass(payload, keygenCommitmentsOverrides{PaillierPublicKey: corruptedKey})
	if err != nil {
		t.Fatal(err)
	}
	out2[0].Payload = mutated
	out2[0] = out2[0].RecomputeTranscriptHash()
	if _, err := kg1.HandleKeygenMessage(out2[0]); err == nil {
		t.Fatal("keygen accepted commitments message with corrupted Paillier public key")
	}
}

// marshalKeygenWithCorruptedKey constructs a wire-encoded keygen commitments
// payload with the given Paillier public key bytes substituted, bypassing
// key validation. Test-only.
