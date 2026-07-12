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
	keygenShareRound        = 2
	keygenConfirmationRound = 3

	presignStartRound          = 1
	presignRound2              = 2
	presignRound3              = 3
	presignIdentificationRound = 4

	refreshStartRound = 1
	refreshShareRound = 2
	reshareStartRound = 1
	reshareShareRound = 2

	signStartRound          = 1
	signIdentificationRound = 2
)

const (
	payloadKeygenCommitments     tss.PayloadType = "cggmp21.secp256k1.keygen.commitments"
	payloadKeygenShare           tss.PayloadType = "cggmp21.secp256k1.keygen.share"
	payloadKeygenConfirmation    tss.PayloadType = "cggmp21.secp256k1.keygen.confirmation"
	payloadPresignRound1         tss.PayloadType = "cggmp21.secp256k1.presign.round1"
	payloadPresignRound1Proof    tss.PayloadType = "cggmp21.secp256k1.presign.round1-proof"
	payloadPresignRound2         tss.PayloadType = "cggmp21.secp256k1.presign.round2"
	payloadPresignRound3         tss.PayloadType = "cggmp21.secp256k1.presign.round3"
	payloadPresignIdentification tss.PayloadType = "cggmp21.secp256k1.presign.identification"
	payloadSignPartial           tss.PayloadType = "cggmp21.secp256k1.sign.partial"
	payloadSignIdentification    tss.PayloadType = "cggmp21.secp256k1.sign.identification"
	payloadRefreshCommitments    tss.PayloadType = "cggmp21.secp256k1.refresh.commitments"
	payloadRefreshShare          tss.PayloadType = "cggmp21.secp256k1.refresh.share"
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
	Context              tss.SigningContext
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
	VerificationShare []byte `wire:"1,bytes,max_bytes=point"`

	PaillierPublicKey *pai.PublicKey      `wire:"2,nested,max_bytes=paillier_public_key"`
	PaillierProof     *zkpai.ModulusProof `wire:"3,nested,max_bytes=paillier_proof"`

	RingPedersenParams *zkpai.RingPedersenParams `wire:"4,nested,max_bytes=ring_pedersen_params"`
	RingPedersenProof  *zkpai.RingPedersenProof  `wire:"5,nested,max_bytes=paillier_proof"`

	KeygenConfirmation  *KeygenConfirmation `wire:"6,record"`
	PaillierFactorProof *zkpai.FactorProof  `wire:"7,nested,optional,max_bytes=zk_proof"`
}

// Clone returns a deep copy of the keySharePartyData.
func (in keySharePartyData) Clone() keySharePartyData {
	return keySharePartyData{
		VerificationShare:   bytes.Clone(in.VerificationShare),
		PaillierPublicKey:   in.PaillierPublicKey.Clone(),
		PaillierProof:       in.PaillierProof.Clone(),
		RingPedersenParams:  in.RingPedersenParams.Clone(),
		RingPedersenProof:   in.RingPedersenProof.Clone(),
		KeygenConfirmation:  in.KeygenConfirmation.Clone(),
		PaillierFactorProof: in.PaillierFactorProof.Clone(),
	}
}

type keyShareState struct {
	Party                  tss.PartyID                       `wire:"1,u32"`                                   // Local owner of the secret signing share.
	Threshold              int                               `wire:"2,u32"`                                   // Number of signers required for CGGMP21 signing.
	Parties                tss.PartySet                      `wire:"3,u32list,max_items=parties"`             // Canonical full participant set for the group key.
	PublicKey              []byte                            `wire:"4,bytes,max_bytes=point"`                 // Parent group public key before request-time derivation.
	ChainCode              []byte                            `wire:"5,bytes,len=32"`                          // HD chain code paired with PublicKey for non-hardened derivation.
	Secret                 *secret.Scalar                    `wire:"6,custom,len=32"`                         // Local ECDSA signing share; never exposed through accessors.
	GroupCommitments       []*secp.Point                     `wire:"7,customlist,len=33,max_items=threshold"` // Public polynomial commitments from keygen/reshare.
	PartyData              map[tss.PartyID]keySharePartyData `wire:"8,map,max_items=parties"`                 // Per-party public material keyed by participant identity.
	PaillierPrivateKey     *pai.PrivateKey                   `wire:"9,custom,max_bytes=paillier_private_key"` // Local Paillier private key; secret-bearing.
	ShareProof             *schnorr.Proof                    `wire:"10,custom,max_bytes=zk_proof"`            // Public proof binding a reshare receiver's share to commitments.
	KeygenTranscriptHash   []byte                            `wire:"11,bytes,len=32"`                         // Transcript hash of the completed keygen or reshare confirmation.
	PaillierProofSessionID tss.SessionID                     `wire:"12,bytes,len=32"`                         // Session ID bound into local Paillier proof transcripts.
	PaillierProofDomain    string                            `wire:"13,string"`                               // Domain label bound into local Paillier proof transcripts.
	LogCiphertext          *big.Int                          `wire:"14,bigpos,max_bytes=paillier_ciphertext"` // Public ciphertext used by auxiliary logarithm proofs.
	LogProof               *zkpai.LogStarProof               `wire:"15,custom,max_bytes=zk_proof"`            // Public proof for the auxiliary logarithm statement.
	ResharePlanHash        []byte                            `wire:"16,bytes"`                                // Reshare plan digest when this share came from reshare.
	PlanHash               []byte                            `wire:"17,bytes,len=32"`                         // Lifecycle plan digest that authorized this key share.
	SecurityParams         SecurityParams                    `wire:"18,record"`                               // Cryptographic profile used to create this share.
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
