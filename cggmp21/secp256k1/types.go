package secp256k1

import (
	"bytes"
	"context"
	"io"
	"math/big"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/secret"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
	"github.com/islishude/tss/internal/zk/schnorr"
)

// The round numbers with named constants
const (
	invalidRound = 0

	keygenStartRound        = 1
	keygenConfirmationRound = 2

	presignStartRound = 1
	presignRound2     = 2
	presignRound3     = 3

	refreshStartRound = 1
	reshareStartRound = 1

	signStartRound = 1
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

// KeySharePublicMetadata is a caller-owned snapshot of non-secret key-share
// metadata that is not scoped to one participant.
type KeySharePublicMetadata struct {
	SecurityParams       SecurityParams
	Party                tss.PartyID
	Threshold            int
	Parties              tss.PartySet
	PublicKey            []byte
	ChainCode            []byte
	GroupCommitments     [][]byte
	PaillierProofSession tss.SessionID
	PaillierProofDomain  string
	ResharePlanHash      []byte
	PlanHash             []byte
	ShareProof           []byte
	KeygenTranscriptHash []byte
	LogCiphertext        []byte
	LogProof             []byte
}

// Clone returns a deep copy of the key-share metadata snapshot.
func (m KeySharePublicMetadata) Clone() KeySharePublicMetadata {
	return KeySharePublicMetadata{
		SecurityParams:       m.SecurityParams,
		Party:                m.Party,
		Threshold:            m.Threshold,
		Parties:              m.Parties.Clone(),
		PublicKey:            bytes.Clone(m.PublicKey),
		ChainCode:            bytes.Clone(m.ChainCode),
		GroupCommitments:     tss.CloneByteSlices(m.GroupCommitments),
		PaillierProofSession: m.PaillierProofSession,
		PaillierProofDomain:  m.PaillierProofDomain,
		ResharePlanHash:      bytes.Clone(m.ResharePlanHash),
		PlanHash:             bytes.Clone(m.PlanHash),
		ShareProof:           bytes.Clone(m.ShareProof),
		KeygenTranscriptHash: bytes.Clone(m.KeygenTranscriptHash),
		LogCiphertext:        bytes.Clone(m.LogCiphertext),
		LogProof:             bytes.Clone(m.LogProof),
	}
}

// PresignPublicMetadata is a caller-owned snapshot of non-secret presign
// metadata that is not scoped to one signer.
type PresignPublicMetadata struct {
	SecurityParams       SecurityParams
	Party                tss.PartyID
	Threshold            int
	Signers              tss.PartySet
	R                    []byte
	LittleR              []byte
	TranscriptHash       []byte
	Context              PresignContext
	ContextHash          []byte
	Derivation           *tss.DerivationResult
	VerificationKey      []byte
	PlanHash             []byte
	PublicKey            []byte
	KeygenTranscriptHash []byte
	PartiesHash          []byte
}

// Clone returns a deep copy of the presign metadata snapshot.
func (m PresignPublicMetadata) Clone() PresignPublicMetadata {
	return PresignPublicMetadata{
		SecurityParams:       m.SecurityParams,
		Party:                m.Party,
		Threshold:            m.Threshold,
		Signers:              m.Signers.Clone(),
		R:                    bytes.Clone(m.R),
		LittleR:              bytes.Clone(m.LittleR),
		TranscriptHash:       bytes.Clone(m.TranscriptHash),
		Context:              m.Context.Clone(),
		ContextHash:          bytes.Clone(m.ContextHash),
		Derivation:           m.Derivation.Clone(),
		VerificationKey:      bytes.Clone(m.VerificationKey),
		PlanHash:             bytes.Clone(m.PlanHash),
		PublicKey:            bytes.Clone(m.PublicKey),
		KeygenTranscriptHash: bytes.Clone(m.KeygenTranscriptHash),
		PartiesHash:          bytes.Clone(m.PartiesHash),
	}
}

// KeyShare is one local CGGMP21-style secp256k1 ECDSA signing share.
//
// Its fields are intentionally opaque. Public metadata is exposed through
// caller-owned snapshots, and per-party public material is exposed by PartyID.
//
// A shallow Go copy of KeyShare is another handle to the same lifecycle state:
// destroying either handle destroys the shared secret material. Session
// completion accessors instead return independently owned key shares.
type KeyShare struct {
	state *keyShareState
}

type keySharePartyData struct {
	verificationShare []byte

	paillierPublicKey *pai.PublicKey
	paillierProof     *zkpai.ModulusProof

	ringPedersenParams *zkpai.RingPedersenParams
	ringPedersenProof  *zkpai.RingPedersenProof

	keygenConfirmation *KeygenConfirmation
}

// Clone returns a deep copy of the keySharePartyData.
func (in keySharePartyData) Clone() keySharePartyData {
	return keySharePartyData{
		verificationShare:  bytes.Clone(in.verificationShare),
		paillierPublicKey:  in.paillierPublicKey.Clone(),
		paillierProof:      in.paillierProof.Clone(),
		ringPedersenParams: in.ringPedersenParams.Clone(),
		ringPedersenProof:  in.ringPedersenProof.Clone(),
		keygenConfirmation: in.keygenConfirmation.Clone(),
	}
}

type keyShareState struct {
	party                  tss.PartyID                       // Local owner of the secret signing share.
	threshold              int                               // Number of signers required for CGGMP21 signing.
	parties                tss.PartySet                      // Canonical full participant set for the group key.
	publicKey              []byte                            // Parent group public key before request-time derivation.
	chainCode              []byte                            // HD chain code paired with publicKey for non-hardened derivation.
	secret                 *secret.Scalar                    // Local ECDSA signing share; never exposed through accessors.
	groupCommitments       []*secp.Point                     // Public polynomial commitments from keygen/reshare.
	partyData              map[tss.PartyID]keySharePartyData // Per-party public material keyed by participant identity.
	paillierPrivateKey     *pai.PrivateKey                   // Local Paillier private key; secret-bearing.
	shareProof             *schnorr.Proof                    // Public proof binding a reshare receiver's share to commitments.
	keygenTranscriptHash   []byte                            // Transcript hash of the completed keygen or reshare confirmation.
	paillierProofSessionID tss.SessionID                     // Session ID bound into local Paillier proof transcripts.
	paillierProofDomain    string                            // Domain label bound into local Paillier proof transcripts.
	logCiphertext          *big.Int                          // Public ciphertext used by auxiliary logarithm proofs.
	logProof               *zkpai.LogStarProof               // Public proof for the auxiliary logarithm statement.
	resharePlanHash        []byte                            // Reshare plan digest when this share came from reshare.
	planHash               []byte                            // Lifecycle plan digest that authorized this key share.
	securityParams         SecurityParams                    // Cryptographic profile used to create this share.
}

// Signature is a canonical low-S secp256k1 ECDSA signature encoded as r and s
// scalars.
// RecoveryID is the compact recovery id in [0,3]. Chain-specific encodings
// such as Ethereum v/yParity should be derived outside this library.
type Signature struct {
	R          []byte `json:"r"`
	S          []byte `json:"s"`
	RecoveryID uint8  `json:"recovery_id"`
}
