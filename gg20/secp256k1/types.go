package secp256k1

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
)

const protocol = "gg20-secp256k1"

const (
	payloadKeygenCommitments = "gg20.secp256k1.keygen.commitments"
	payloadKeygenShare       = "gg20.secp256k1.keygen.share"
	payloadPresignCommitment = "gg20.secp256k1.presign.commitments"
	payloadPresignShare      = "gg20.secp256k1.presign.share"
	payloadSignShare         = "gg20.secp256k1.sign.share"
)

const ExperimentalSecurityNotice = "experimental threshold ECDSA path: signing reconstructs secret and nonce shares; not production GG20 Paillier/MtA/ZK"

type VerificationShare struct {
	Party     tss.PartyID `json:"party"`
	PublicKey []byte      `json:"public_key"`
}

type KeyShare struct {
	Version            uint16              `json:"version"`
	Party              tss.PartyID         `json:"party"`
	Threshold          int                 `json:"threshold"`
	Parties            []tss.PartyID       `json:"parties"`
	PublicKey          []byte              `json:"public_key"`
	Secret             []byte              `json:"secret"`
	GroupCommitments   [][]byte            `json:"group_commitments"`
	VerificationShares []VerificationShare `json:"verification_shares"`
	SecurityNotice     string              `json:"security_notice"`
}

type Signature struct {
	R []byte `json:"r"`
	S []byte `json:"s"`
}

func (k *KeyShare) Algorithm() tss.Algorithm {
	return tss.AlgorithmGG20Secp256k1
}

func (k *KeyShare) PartyID() tss.PartyID {
	if k == nil {
		return 0
	}
	return k.Party
}

func (k *KeyShare) PublicKeyBytes() []byte {
	if k == nil {
		return nil
	}
	return tss.CloneBytes(k.PublicKey)
}

func (k *KeyShare) MarshalBinary() ([]byte, error) {
	if err := k.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(k)
}

func UnmarshalKeyShare(in []byte) (*KeyShare, error) {
	var k KeyShare
	if err := json.Unmarshal(in, &k); err != nil {
		return nil, err
	}
	if err := k.Validate(); err != nil {
		return nil, err
	}
	return &k, nil
}

func (k *KeyShare) Validate() error {
	if k == nil {
		return errors.New("nil key share")
	}
	if k.Version != tss.Version {
		return fmt.Errorf("unexpected key share version %d", k.Version)
	}
	if k.Threshold <= 0 || k.Threshold > len(k.Parties) {
		return errors.New("invalid threshold")
	}
	if !tss.ContainsParty(k.Parties, k.Party) {
		return errors.New("key share party is not in participant set")
	}
	if _, err := secp.PointFromBytes(k.PublicKey); err != nil {
		return fmt.Errorf("invalid group public key: %w", err)
	}
	if _, err := secp.ParseScalar(k.Secret); err != nil {
		return fmt.Errorf("invalid secret scalar: %w", err)
	}
	if len(k.GroupCommitments) != k.Threshold {
		return errors.New("group commitments length must equal threshold")
	}
	if len(k.VerificationShares) != len(k.Parties) {
		return errors.New("verification share count must equal party count")
	}
	seen := make(map[tss.PartyID]struct{}, len(k.VerificationShares))
	for _, vs := range k.VerificationShares {
		if !tss.ContainsParty(k.Parties, vs.Party) {
			return fmt.Errorf("verification share for non-participant %d", vs.Party)
		}
		if _, ok := seen[vs.Party]; ok {
			return fmt.Errorf("duplicate verification share for %d", vs.Party)
		}
		seen[vs.Party] = struct{}{}
		if _, err := secp.PointFromBytes(vs.PublicKey); err != nil {
			return fmt.Errorf("invalid verification share for %d: %w", vs.Party, err)
		}
	}
	return nil
}

func (k *KeyShare) Destroy() {
	if k == nil {
		return
	}
	tss.SensitiveBytes(k.Secret).Destroy()
}

func (k *KeyShare) secretBig() (*big.Int, error) {
	return secp.ParseScalar(k.Secret)
}

func scalarBytes(x *big.Int) []byte {
	return secp.ScalarBytes(x)
}

func envelope(config tss.ThresholdConfig, round uint8, from, to tss.PartyID, payloadType string, payload []byte, confidential bool) tss.Envelope {
	return tss.Envelope{
		Protocol:             protocol,
		Version:              tss.Version,
		SessionID:            config.SessionID,
		Round:                round,
		From:                 from,
		To:                   to,
		PayloadType:          payloadType,
		Payload:              payload,
		ConfidentialRequired: confidential,
	}.WithTranscriptHash()
}
