package secp256k1

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/islishude/tss"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/secret"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

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

// generatePaillierKey creates a Paillier key using the production GenerateKey
// when bits meet the production floor, or GenerateKeyForTest when running with
// reduced security parameters (e.g. integration tests).
func generatePaillierKey(ctx context.Context, reader io.Reader, bits int) (*pai.PrivateKey, error) {
	if bits >= pai.MinProductionModulusBits {
		return pai.GenerateKey(ctx, reader, bits)
	}
	return pai.GenerateKeyForTest(ctx, reader, bits)
}

// VerificationShare is a caller-owned snapshot of one participant public ECDSA
// verification share.
type VerificationShare struct {
	Party     tss.PartyID `json:"party" wire:"1,u32"`
	PublicKey []byte      `json:"public_key" wire:"2,bytes,max_bytes=point"`
}

// Clone returns a deep copy of VerificationShare
func (v VerificationShare) Clone() VerificationShare {
	return VerificationShare{
		Party:     v.Party,
		PublicKey: bytes.Clone(v.PublicKey),
	}
}

// PaillierPublicShare is a caller-owned snapshot of a participant Paillier
// public key and proof.
type PaillierPublicShare struct {
	Party     tss.PartyID `json:"party" wire:"1,u32"`
	PublicKey []byte      `json:"public_key" wire:"2,bytes,max_bytes=paillier_public_key"`
	Proof     []byte      `json:"proof" wire:"3,bytes,max_bytes=zk_proof"`
}

// Clone returns a deep copy of the PaillierPublicShare.
func (p PaillierPublicShare) Clone() PaillierPublicShare {
	return PaillierPublicShare{
		Party:     p.Party,
		PublicKey: bytes.Clone(p.PublicKey),
		Proof:     bytes.Clone(p.Proof),
	}
}

// SignVerifyShare records per-party verification material produced during presign
// round 3. It is bound to the presign transcript via the signprep proof and used
// during online signing to verify each partial independently.
type SignVerifyShare struct {
	Party    tss.PartyID `json:"party" wire:"1,u32"`
	KPoint   []byte      `json:"k_point" wire:"2,bytes,max_bytes=point"`
	ChiPoint []byte      `json:"chi_point" wire:"3,bytes,max_bytes=point"`
	Proof    []byte      `json:"proof" wire:"4,bytes,max_bytes=signprep_proof"`
}

// Clone returns a deep copy of the SignVerifyShare.
func (s SignVerifyShare) Clone() SignVerifyShare {
	return SignVerifyShare{
		Party:    s.Party,
		KPoint:   bytes.Clone(s.KPoint),
		ChiPoint: bytes.Clone(s.ChiPoint),
		Proof:    bytes.Clone(s.Proof),
	}
}

// RingPedersenPublicShare is a caller-owned snapshot of a participant
// Ring-Pedersen parameters and proof.
type RingPedersenPublicShare struct {
	Party  tss.PartyID `json:"party" wire:"1,u32"`
	Params []byte      `json:"params" wire:"2,bytes,max_bytes=ring_pedersen_params"`
	Proof  []byte      `json:"proof" wire:"3,bytes,max_bytes=paillier_proof"`
}

// Clone returns a deep copy of the RingPedersenPublicShare.
func (r RingPedersenPublicShare) Clone() RingPedersenPublicShare {
	return RingPedersenPublicShare{
		Party:  r.Party,
		Params: bytes.Clone(r.Params),
		Proof:  bytes.Clone(r.Proof),
	}
}

// KeyShare is one local CGGMP21-style secp256k1 ECDSA signing share.
//
// Its fields are intentionally opaque. Accessors that return slices, maps, or
// nested records return caller-owned deep copies.
//
// A shallow Go copy of KeyShare is another handle to the same lifecycle state:
// destroying either handle destroys the shared secret material. Session
// completion accessors instead return independently owned key shares.
type KeyShare struct {
	state *keyShareState
}

type keyShareState struct {
	securityParams         SecurityParams               // Cryptographic profile used to create this share.
	party                  tss.PartyID                  // Local owner of the secret signing share.
	threshold              int                          // Number of signers required for CGGMP21 signing.
	parties                tss.PartySet                 // Canonical full participant set for the group key.
	publicKey              []byte                       // Parent group public key before request-time derivation.
	chainCode              []byte                       // HD chain code paired with publicKey for non-hardened derivation.
	secret                 *secret.Scalar               // Local ECDSA signing share; never exposed through accessors.
	groupCommitments       [][]byte                     // Public polynomial commitments from keygen/reshare.
	verificationShares     []VerificationShare          // Per-party public verification shares derived from commitments.
	paillierPublicKey      *pai.PublicKey               // Local Paillier public key used by peers in MtA.
	paillierPrivateKey     *pai.PrivateKey              // Local Paillier private key; secret-bearing.
	paillierProof          *zkpai.ModulusProof          // Proof that paillierPublicKey satisfies the configured security profile.
	paillierPublicKeys     []paillierPublicMaterial     // Typed public Paillier material for every participant.
	ringPedersenParams     *zkpai.RingPedersenParams    // Local Ring-Pedersen parameters paired with Paillier material.
	ringPedersenProof      *zkpai.RingPedersenProof     // Proof for local Ring-Pedersen parameter generation.
	ringPedersenPublic     []ringPedersenPublicMaterial // Typed Ring-Pedersen material for every participant.
	paillierProofSessionID tss.SessionID                // Session ID bound into local Paillier proof transcripts.
	paillierProofDomain    string                       // Domain label bound into local Paillier proof transcripts.
	resharePlanHash        []byte                       // Reshare plan digest when this share came from reshare.
	shareProof             []byte                       // Public proof binding a reshare receiver's share to commitments.
	planHash               []byte                       // Lifecycle plan digest that authorized this key share.
	keygenTranscriptHash   []byte                       // Transcript hash of the completed keygen or reshare confirmation.
	logCiphertext          []byte                       // Public ciphertext used by auxiliary logarithm proofs.
	logProof               []byte                       // Public proof for the auxiliary logarithm statement.
	keygenConfirmations    []*KeygenConfirmation        // Confirmation set proving every party accepted the keygen.
}

// validateSignVerifyShares checks that the verify shares set matches the signer
// set: one canonically ordered entry per signer, no extras, no duplicates,
// canonical point encodings, and non-empty proofs within size limits.
func validateSignVerifyShares(signers tss.PartySet, shares []SignVerifyShare, limits Limits) error {
	if len(shares) != len(signers) {
		return fmt.Errorf("verify shares count %d != signers %d", len(shares), len(signers))
	}
	totalBytes := 4 // recordlist item count
	seen := make(map[tss.PartyID]bool, len(shares))
	for i, share := range shares {
		if !tss.ContainsParty(signers, share.Party) {
			return fmt.Errorf("verify share for non-signer party %d", share.Party)
		}
		if seen[share.Party] {
			return fmt.Errorf("duplicate verify share for party %d", share.Party)
		}
		seen[share.Party] = true
		if share.Party != signers[i] {
			return fmt.Errorf("verify share party %d out of canonical signer order at index %d", share.Party, i)
		}
		if err := share.ValidateWithLimits(limits); err != nil {
			return fmt.Errorf("verify share party %d: %w", share.Party, err)
		}
		totalBytes += 4 + signVerifyShareRecordSize(share)
	}
	if totalBytes > limits.SignPrep.MaxVerifySharesBytes {
		return fmt.Errorf("verify shares too large: %d > %d", totalBytes, limits.SignPrep.MaxVerifySharesBytes)
	}
	return nil
}

// Signature is a secp256k1 ECDSA signature encoded as r and s scalars.
// RecoveryID is the compact recovery id in [0,3]. Chain-specific encodings
// such as Ethereum v/yParity should be derived outside this library.
type Signature struct {
	R          []byte `json:"r"`
	S          []byte `json:"s"`
	RecoveryID uint8  `json:"recovery_id"`
}
