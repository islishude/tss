package ed25519

import (
	"errors"
	"fmt"
	"io"
	"math/big"
	"slices"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
	"github.com/islishude/tss/internal/secret"
)

const (
	payloadKeygenCommitments  tss.PayloadType = "frost.ed25519.keygen.commitments"
	payloadKeygenShare        tss.PayloadType = "frost.ed25519.keygen.share"
	payloadKeygenConfirmation tss.PayloadType = "frost.ed25519.keygen.confirmation"
	payloadSignCommitment     tss.PayloadType = "frost.ed25519.sign.commitment"
	payloadSignPartial        tss.PayloadType = "frost.ed25519.sign.partial"
)

// VerificationShare is a caller-owned snapshot of a participant public share
// derived from DKG commitments.
type VerificationShare struct {
	Party     tss.PartyID            `json:"party" wire:"1,u32"`
	PublicKey VerificationSharePoint `json:"public_key" wire:"2,custom,len=32"`
}

// Clone returns a deep copy of VerificationShare.
func (v VerificationShare) Clone() VerificationShare {
	return VerificationShare{
		Party:     v.Party,
		PublicKey: v.PublicKey.Clone(),
	}
}

// KeySharePublicMetadata is a caller-owned snapshot of non-secret key-share
// metadata that is not scoped to one participant.
type KeySharePublicMetadata struct {
	Party                tss.PartyID
	Threshold            int
	Parties              tss.PartySet
	PublicKey            PublicKeyPoint
	ChainCode            []byte
	GroupCommitments     [][]byte
	KeygenSessionID      tss.SessionID
	KeygenTranscriptHash []byte
	PlanHash             []byte
}

// Clone returns a deep copy of the key-share metadata snapshot.
func (m KeySharePublicMetadata) Clone() KeySharePublicMetadata {
	return KeySharePublicMetadata{
		Party:                m.Party,
		Threshold:            m.Threshold,
		Parties:              m.Parties.Clone(),
		PublicKey:            m.PublicKey.Clone(),
		ChainCode:            slices.Clone(m.ChainCode),
		GroupCommitments:     tss.CloneByteSlices(m.GroupCommitments),
		KeygenSessionID:      m.KeygenSessionID,
		KeygenTranscriptHash: slices.Clone(m.KeygenTranscriptHash),
		PlanHash:             slices.Clone(m.PlanHash),
	}
}

// KeyShare is one local FROST Ed25519 signing share.
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
	verificationShare  verificationSharePoint `wire:"1,custom,len=32"`
	keygenConfirmation *KeygenConfirmation    `wire:"2,record,optional"`
}

// Clone returns a deep copy of keySharePartyData.
func (in keySharePartyData) Clone() keySharePartyData {
	return keySharePartyData{
		verificationShare:  in.verificationShare.Clone(),
		keygenConfirmation: in.keygenConfirmation.Clone(),
	}
}

type keyShareState struct {
	party                tss.PartyID                       `wire:"1,u32"`                        // Local owner of the secret signing share.
	threshold            int                               `wire:"2,u32"`                        // Number of signers required for FROST signing.
	parties              tss.PartySet                      `wire:"3,u32list"`                    // Canonical full participant set for the group key.
	publicKey            publicKeyPoint                    `wire:"4,custom,len=32"`              // Parent group public key before request-time derivation.
	chainCode            []byte                            `wire:"5,bytes"`                      // HD chain code paired with publicKey for non-hardened derivation.
	secret               *secret.Scalar                    `wire:"6,custom,len=32"`              // Local Ed25519 signing share; never exposed through accessors.
	groupCommitments     groupCommitments                  `wire:"7,custom,max_items=threshold"` // Public polynomial commitments from keygen/reshare.
	partyData            map[tss.PartyID]keySharePartyData `wire:"8,map,max_items=parties"`      // Per-party public material keyed by participant identity.
	keygenSessionID      tss.SessionID                     `wire:"9,bytes,len=32"`               // Session that produced this key share.
	keygenTranscriptHash []byte                            `wire:"10,bytes"`                     // Transcript hash of completed keygen/reshare confirmation.
	planHash             []byte                            `wire:"11,bytes,len=32"`              // Lifecycle plan digest that authorized this key share.
}

func scalarBytes(x *big.Int) ([]byte, error) {
	s, err := edcurve.ScalarFromBig(x)
	if err != nil {
		return nil, err
	}
	return s.Bytes(), nil
}

// SignOptions controls optional signing behavior.
type SignOptions struct {
	// Context binds signing to a key, chain, derivation path, policy domain,
	// and message domain.
	Context tss.SigningContext

	// NonceReader supplies fresh randomness for FROST signing nonces. If nil,
	// crypto/rand.Reader is used.
	NonceReader io.Reader

	// Limits overrides the default protocol limits. When nil, DefaultLimits is used.
	Limits *Limits
}

// DerivePublicKey returns the child Ed25519 public key produced by adding
// the additive scalar shift times the base point to publicKey.
func DerivePublicKey(publicKey, additiveShift []byte) ([]byte, error) {
	base, err := edcurve.PointFromBytes(publicKey)
	if err != nil {
		return nil, err
	}
	if len(additiveShift) == 0 {
		return base.Bytes(), nil
	}
	shift, err := edcurve.ScalarFromCanonical(additiveShift)
	if err != nil {
		return nil, fmt.Errorf("invalid additive shift: %w", err)
	}
	shifted := edcurve.AddPoints(base, fed.NewIdentityPoint().ScalarBaseMult(shift))
	if edcurve.IsIdentity(shifted) {
		return nil, errors.New("derived public key is identity")
	}
	return shifted.Bytes(), nil
}
