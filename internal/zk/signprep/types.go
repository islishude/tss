package signprep

import (
	"bytes"
	"math/big"
	"slices"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/secret"
)

// Statement is the public input for a signprep proof.
type Statement struct {
	Protocol             tss.ProtocolID
	SessionID            tss.SessionID
	Party                tss.PartyID
	Signers              tss.PartySet
	PlanHash             []byte
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

// Clone returns a deep copy of Statement
func (stmt Statement) Clone() Statement {
	stmt.Signers = slices.Clone(stmt.Signers)
	stmt.PlanHash = bytes.Clone(stmt.PlanHash)
	stmt.ContextHash = bytes.Clone(stmt.ContextHash)
	stmt.AdditiveShift = bytes.Clone(stmt.AdditiveShift)
	stmt.PublicKey = bytes.Clone(stmt.PublicKey)
	stmt.KeygenTranscriptHash = bytes.Clone(stmt.KeygenTranscriptHash)
	stmt.PartiesHash = bytes.Clone(stmt.PartiesHash)
	stmt.EncK = bytes.Clone(stmt.EncK)
	stmt.PaillierPublicKey = bytes.Clone(stmt.PaillierPublicKey)
	stmt.Round1Echo = bytes.Clone(stmt.Round1Echo)
	stmt.Gamma = bytes.Clone(stmt.Gamma)
	stmt.Delta = bytes.Clone(stmt.Delta)
	stmt.LittleR = bytes.Clone(stmt.LittleR)
	stmt.R = bytes.Clone(stmt.R)
	stmt.KPoint = bytes.Clone(stmt.KPoint)
	stmt.ChiPoint = bytes.Clone(stmt.ChiPoint)
	stmt.XBarPoint = bytes.Clone(stmt.XBarPoint)
	return stmt
}

// Witness is the secret input for a signprep proof.
type Witness struct {
	KShare   *big.Int
	MTASum   *big.Int
	ChiShare *big.Int
}

// Clone returns a deep copy of Witness
func (w Witness) Clone() Witness {
	return Witness{
		KShare:   new(big.Int).Set(w.KShare),
		MTASum:   new(big.Int).Set(w.MTASum),
		ChiShare: new(big.Int).Set(w.ChiShare),
	}
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
func (Proof) WireVersion() uint16 { return proofWireVersion }
