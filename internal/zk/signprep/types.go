package signprep

import (
	"math/big"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/secret"
)

// Statement is the public input for a signprep proof.
type Statement struct {
	Protocol             tss.ProtocolID
	SessionID            tss.SessionID
	Party                tss.PartyID
	Signers              []tss.PartyID
	ContextHash          []byte
	AdditiveShift        []byte
	PublicKey            []byte
	KeygenTranscriptHash []byte
	PartiesHash          []byte
	EncK                 []byte
	PaillierPublicKey    []byte
	Round1Echo           []byte
	Gamma                []byte
	Delta                []byte
	LittleR              []byte
	R                    []byte
	KPoint               []byte
	ChiPoint             []byte
	XBarPoint            []byte
}

// Witness is the secret input for a signprep proof.
type Witness struct {
	KShare   *big.Int
	MTASum   *big.Int
	ChiShare *big.Int
}

// Proof is a CGGMP21 signprep proof.
type Proof struct {
	MPoint       []byte         `wire:"1,bytes"`
	KCommitment  []byte         `wire:"2,bytes"`
	MCommitment  []byte         `wire:"3,bytes"`
	DLEQA1       []byte         `wire:"4,bytes"`
	DLEQA2       []byte         `wire:"5,bytes"`
	KResponse    *secret.Scalar `wire:"6,custom,len=32"`
	MResponse    []byte         `wire:"7,bytes"`
	DLEQResponse *secret.Scalar `wire:"8,custom,len=32"`
}

// WireType returns the canonical wire type identifier for Proof.
func (Proof) WireType() string { return proofWireType }

// WireVersion returns the wire format version for Proof.
func (Proof) WireVersion() uint16 { return proofVersion }
