package ed25519

import (
	"errors"
	"fmt"

	"github.com/islishude/tss"

	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/wire"
)

const (
	keyShareWireType    = "frost.ed25519.keyshare"
	keyShareWireVersion = 1
)

// keyShareWire is the wire DTO for KeyShare.
type keyShareWire struct {
	Party                tss.PartyID                           `wire:"1,u32"`
	Threshold            int                                   `wire:"2,u32"`
	Parties              tss.PartySet                          `wire:"3,u32list"`
	PublicKey            edcurve.WirePoint                     `wire:"4,custom,len=32"`
	ChainCode            []byte                                `wire:"5,bytes"`
	Secret               *secret.Scalar                        `wire:"6,custom,len=32"`
	GroupCommitments     [][]byte                              `wire:"7,byteslist,max_bytes=point,max_items=threshold"`
	PartyData            map[tss.PartyID]keySharePartyDataWire `wire:"8,map,max_items=parties"`
	KeygenSessionID      tss.SessionID                         `wire:"9,bytes,len=32"`
	KeygenTranscriptHash []byte                                `wire:"10,bytes"`
	PlanHash             []byte                                `wire:"11,bytes,len=32"`
}

type keySharePartyDataWire struct {
	VerificationShare  VerificationSharePoint `wire:"1,custom,len=32"`
	KeygenConfirmation *KeygenConfirmation    `wire:"2,record,optional"`
}

// WireType returns the canonical wire type identifier for keyShareWire.
func (keyShareWire) WireType() string { return keyShareWireType }

// WireVersion returns the wire format version for keyShareWire.
func (keyShareWire) WireVersion() uint16 { return keyShareWireVersion }

func encodeKeyShareWire(k *KeyShare) (*keyShareWire, error) {
	partyData := make(map[tss.PartyID]keySharePartyDataWire, len(k.state.partyData))
	for id, data := range k.state.partyData {
		if data.keygenConfirmation != nil && data.keygenConfirmation.Sender != id {
			return nil, fmt.Errorf("keygen confirmation sender %d does not match party data key %d", data.keygenConfirmation.Sender, id)
		}
		partyData[id] = keySharePartyDataWire{
			VerificationShare:  data.verificationShare.Clone(),
			KeygenConfirmation: data.keygenConfirmation.Clone(),
		}
	}
	return &keyShareWire{
		Party:                k.state.party,
		Threshold:            k.state.threshold,
		Parties:              k.state.parties,
		PublicKey:            edcurve.WirePoint{P: k.state.publicKey.Point()},
		ChainCode:            k.state.chainCode,
		Secret:               k.state.secret,
		GroupCommitments:     k.state.groupCommitments.BytesList(),
		PartyData:            partyData,
		KeygenSessionID:      k.state.keygenSessionID,
		KeygenTranscriptHash: k.state.keygenTranscriptHash,
		PlanHash:             k.state.planHash,
	}, nil
}

func decodeKeyShareWire(w *keyShareWire) (*keyShareState, error) {
	if _, err := edScalarFromSecret(w.Secret); err != nil {
		return nil, fmt.Errorf("invalid secret scalar: %w", err)
	}
	publicKey, err := newPublicKeyPointFromPoint(w.PublicKey.P)
	if err != nil {
		return nil, fmt.Errorf("invalid group public key: %w", err)
	}
	groupCommitments, err := newGroupCommitmentsFromBytesList(w.GroupCommitments, w.Threshold)
	if err != nil {
		return nil, fmt.Errorf("invalid group commitments: %w", err)
	}
	if len(w.PartyData) != len(w.Parties) {
		return nil, fmt.Errorf("party data count %d != party count %d", len(w.PartyData), len(w.Parties))
	}
	partyData := make(map[tss.PartyID]keySharePartyData, len(w.PartyData))
	for _, id := range w.Parties {
		if id == tss.BroadcastPartyId {
			return nil, errors.New("broadcast party cannot have key share party data")
		}
		wireData, ok := w.PartyData[id]
		if !ok {
			return nil, fmt.Errorf("missing party data for participant %d", id)
		}
		confirmation := wireData.KeygenConfirmation.Clone()
		if confirmation != nil && confirmation.Sender != id {
			return nil, fmt.Errorf("keygen confirmation sender %d does not match party data key %d", confirmation.Sender, id)
		}
		partyData[id] = keySharePartyData{
			verificationShare:  wireData.VerificationShare.Clone(),
			keygenConfirmation: confirmation,
		}
	}
	for id := range w.PartyData {
		if id == tss.BroadcastPartyId {
			return nil, errors.New("broadcast party cannot have key share party data")
		}
		if !tss.ContainsParty(w.Parties, id) {
			return nil, fmt.Errorf("party data for non-participant %d", id)
		}
	}
	return &keyShareState{
		party:                w.Party,
		threshold:            w.Threshold,
		parties:              w.Parties,
		publicKey:            publicKey,
		chainCode:            w.ChainCode,
		secret:               w.Secret,
		groupCommitments:     groupCommitments,
		partyData:            partyData,
		keygenSessionID:      w.KeygenSessionID,
		keygenTranscriptHash: w.KeygenTranscriptHash,
		planHash:             w.PlanHash,
	}, nil
}

// WireType returns the canonical wire type identifier for KeyShare.
func (*KeyShare) WireType() string { return keyShareWireType }

// WireVersion returns the wire format version for KeyShare.
func (*KeyShare) WireVersion() uint16 { return keyShareWireVersion }

// MarshalWireMessage encodes KeyShare through its private wire DTO.
func (k *KeyShare) MarshalWireMessage(opts ...wire.MarshalOption) ([]byte, error) {
	w, err := encodeKeyShareWire(k)
	if err != nil {
		return nil, err
	}
	return wire.Marshal(w, opts...)
}

// UnmarshalWireMessage decodes KeyShare through its private wire DTO.
func (k *KeyShare) UnmarshalWireMessage(in []byte, opts ...wire.UnmarshalOption) error {
	var w keyShareWire
	if err := wire.Unmarshal(in, &w, opts...); err != nil {
		return err
	}
	state, err := decodeKeyShareWire(&w)
	if err != nil {
		return err
	}
	k.state = state
	return nil
}

// ValidateWithLimits checks KeyShare against explicit local resource limits.
func (k *KeyShare) ValidateWithLimits(limits Limits) error {
	if k == nil || k.state == nil {
		return errors.New("nil key share")
	}
	if k.state.threshold > limits.Threshold.MaxThreshold {
		return fmt.Errorf("threshold too large: %d > %d", k.state.threshold, limits.Threshold.MaxThreshold)
	}
	if len(k.state.parties) > limits.Threshold.MaxParties {
		return fmt.Errorf("parties too large: %d > %d", len(k.state.parties), limits.Threshold.MaxParties)
	}
	if k.state.groupCommitments.Len() > limits.Threshold.MaxThreshold {
		return fmt.Errorf("group commitments too large: %d > %d", k.state.groupCommitments.Len(), limits.Threshold.MaxThreshold)
	}
	for i, c := range k.state.groupCommitments.BytesList() {
		if len(c) > limits.Curve.MaxPointBytes {
			return fmt.Errorf("group commitment %d too large: %d > %d", i, len(c), limits.Curve.MaxPointBytes)
		}
	}
	if len(k.state.partyData) > limits.Threshold.MaxParties {
		return fmt.Errorf("party data too large: %d > %d", len(k.state.partyData), limits.Threshold.MaxParties)
	}
	confirmationCount := 0
	for id, data := range k.state.partyData {
		encoded := data.verificationShare.Bytes()
		if len(encoded) > limits.Curve.MaxPointBytes {
			return fmt.Errorf("verification share for party %d too large: %d > %d", id, len(encoded), limits.Curve.MaxPointBytes)
		}
		if data.keygenConfirmation != nil {
			confirmationCount++
		}
	}
	if confirmationCount > limits.Threshold.MaxParties {
		return fmt.Errorf("keygen confirmations too large: %d > %d", confirmationCount, limits.Threshold.MaxParties)
	}
	return k.ValidateConsistency()
}

// Clone returns an independently owned deep copy of the key share.
//
// The clone contains secret material and must be destroyed separately when it is
// no longer needed. Destroying the clone does not destroy the original, and
// destroying the original does not destroy the clone.
func (k *KeyShare) Clone() *KeyShare {
	return cloneKeyShareValue(k)
}
