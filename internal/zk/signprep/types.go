package signprep

import (
	"math/big"

	"github.com/islishude/tss"
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
	MPoint       []byte
	KCommitment  []byte
	MCommitment  []byte
	DLEQA1       []byte
	DLEQA2       []byte
	KResponse    []byte
	MResponse    []byte
	DLEQResponse []byte
}
