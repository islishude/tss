package secp256k1

import (
	"context"
	"io"
	"slices"

	"github.com/islishude/tss"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/secret"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

const protocol = tss.ProtocolCGGMP21Secp256k1

const (
	payloadKeygenCommitments  tss.PayloadType = "cggmp21.secp256k1.keygen.commitments"
	payloadKeygenShare        tss.PayloadType = "cggmp21.secp256k1.keygen.share"
	payloadKeygenConfirmation tss.PayloadType = "cggmp21.secp256k1.keygen.confirmation"
	payloadPresignRound1      tss.PayloadType = "cggmp21.secp256k1.presign.round1"
	payloadPresignRound1Proof tss.PayloadType = "cggmp21.secp256k1.presign.round1-proof"
	payloadPresignRound2      tss.PayloadType = "cggmp21.secp256k1.presign.round2"
	payloadPresignRound3      tss.PayloadType = "cggmp21.secp256k1.presign.round3"
	payloadSignPartial        tss.PayloadType = "cggmp21.secp256k1.sign.partial"
	payloadRefreshCommitments tss.PayloadType = "cggmp21.secp256k1.refresh.commitments"
	payloadRefreshShare       tss.PayloadType = "cggmp21.secp256k1.refresh.share"
)

// defaultPaillierBits returns the Paillier modulus size to use for key
// generation, derived from the active CGGMP security parameters.
func defaultPaillierBits() int {
	return zkpai.ActiveSecurityParams().MinPaillierBits
}

// generatePaillierKey creates a Paillier key using the production GenerateKey
// when bits meet the production floor, or GenerateKeyForTest when running with
// reduced security parameters (e.g. integration tests).
func generatePaillierKey(ctx context.Context, reader io.Reader, bits int) (*pai.PrivateKey, error) {
	if bits >= pai.MinProductionModulusBits {
		return pai.GenerateKey(ctx, reader, bits)
	}
	return pai.GenerateKeyForTest(ctx, reader, bits)
}

// VerificationShare is one participant public ECDSA verification share.
type VerificationShare struct {
	Party     tss.PartyID `json:"party"`
	PublicKey []byte      `json:"public_key"`
}

// PaillierPublicShare records a participant Paillier public key and proof.
type PaillierPublicShare struct {
	Party     tss.PartyID `json:"party"`
	PublicKey []byte      `json:"public_key"`
	Proof     []byte      `json:"proof"`
}

// Clone returns a deep copy of the PaillierPublicShare.
func (p PaillierPublicShare) Clone() PaillierPublicShare {
	return PaillierPublicShare{
		Party:     p.Party,
		PublicKey: slices.Clone(p.PublicKey),
		Proof:     slices.Clone(p.Proof),
	}
}

// RingPedersenPublicShare records a participant Ring-Pedersen parameters and proof.
type RingPedersenPublicShare struct {
	Party  tss.PartyID `json:"party"`
	Params []byte      `json:"params"`
	Proof  []byte      `json:"proof"`
}

// Clone returns a deep copy of the RingPedersenPublicShare.
func (r RingPedersenPublicShare) Clone() RingPedersenPublicShare {
	return RingPedersenPublicShare{
		Party:  r.Party,
		Params: slices.Clone(r.Params),
		Proof:  slices.Clone(r.Proof),
	}
}

// KeyShare is one local CGGMP21-style secp256k1 ECDSA signing share.
//
// # Immutability contract
//
// After construction, after [KeyShare.Validate], or after receiving a KeyShare
// from any session method, callers MUST NOT mutate the exported []byte fields
// (PublicKey, ChainCode, GroupCommitments, PaillierPublicKey, PaillierProof,
// RingPedersenParams, RingPedersenProof, ShareProof, KeygenTranscriptHash,
// LogCiphertext, LogProof, KeygenConfirmations). Mutation breaks post-validation
// invariants and can cause signature failures, proof verification errors, or
// incorrect blame attribution.
//
// Use [KeyShare.Clone] to obtain a mutable deep copy. Use the copy-returning
// getters ([KeyShare.PublicKeyBytes], [KeyShare.ChainCodeBytes],
// [KeyShare.GroupCommitmentsCopy], [KeyShare.ShareProofBytes]) when only
// read access is needed.
//
// Fields are exported for binary encoding via [KeyShare.MarshalBinary]; JSON
// encoding is intentionally rejected by [KeyShare.MarshalJSON] to prevent
// accidental exposure of secret material.
type KeyShare struct {
	Version                uint16
	Party                  tss.PartyID
	Threshold              int
	Parties                []tss.PartyID
	PublicKey              []byte
	ChainCode              []byte
	secret                 *secret.Scalar
	GroupCommitments       [][]byte
	VerificationShares     []VerificationShare
	PaillierPublicKey      []byte
	paillierPrivateKey     []byte
	PaillierProof          []byte
	PaillierPublicKeys     []PaillierPublicShare
	RingPedersenParams     []byte
	RingPedersenProof      []byte
	RingPedersenPublic     []RingPedersenPublicShare
	PaillierProofSessionID tss.SessionID
	PaillierProofDomain    string
	ShareProof             []byte
	KeygenTranscriptHash   []byte
	LogCiphertext          []byte
	LogProof               []byte
	KeygenConfirmations    [][]byte
}

// Signature is a secp256k1 ECDSA signature encoded as r and s scalars.
type Signature struct {
	R []byte `json:"r"`
	S []byte `json:"s"`
}
