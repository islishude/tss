package secp256k1

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
	"github.com/islishude/tss/internal/zk/schnorr"
)

const protocol = "cggmp21-secp256k1"

const (
	payloadKeygenCommitments = "cggmp21.secp256k1.keygen.commitments"
	payloadKeygenShare       = "cggmp21.secp256k1.keygen.share"
	payloadPresignRound1     = "cggmp21.secp256k1.presign.round1"
	payloadPresignRound2     = "cggmp21.secp256k1.presign.round2"
	payloadPresignRound3     = "cggmp21.secp256k1.presign.round3"
	payloadSignPartial       = "cggmp21.secp256k1.sign.partial"
)

// ExperimentalSecurityNotice is attached to CGGMP21 artifacts until external audit.
const ExperimentalSecurityNotice = "experimental CGGMP21-style threshold ECDSA path: Paillier MtA/ZK proof implementation is unaudited; independent audit required"

// DefaultPaillierBits is the production default Paillier modulus size.
const DefaultPaillierBits = 2048

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

// KeyShare is one local CGGMP21-style secp256k1 ECDSA signing share.
type KeyShare struct {
	Version              uint16                `json:"version"`
	Party                tss.PartyID           `json:"party"`
	Threshold            int                   `json:"threshold"`
	Parties              []tss.PartyID         `json:"parties"`
	PublicKey            []byte                `json:"public_key"`
	ChainCode            []byte                `json:"chain_code,omitempty"`
	Secret               []byte                `json:"secret"`
	GroupCommitments     [][]byte              `json:"group_commitments"`
	VerificationShares   []VerificationShare   `json:"verification_shares"`
	PaillierPublicKey    []byte                `json:"paillier_public_key,omitempty"`
	PaillierPrivateKey   []byte                `json:"paillier_private_key,omitempty"`
	PaillierProof        []byte                `json:"paillier_proof,omitempty"`
	PaillierPublicKeys   []PaillierPublicShare `json:"paillier_public_keys,omitempty"`
	ShareProof           []byte                `json:"share_proof,omitempty"`
	KeygenTranscriptHash []byte                `json:"keygen_transcript_hash,omitempty"`
	SecurityNotice       string                `json:"security_notice"`
}

// Signature is a secp256k1 ECDSA signature encoded as r and s scalars.
type Signature struct {
	R []byte `json:"r"`
	S []byte `json:"s"`
}

// Algorithm returns the common algorithm identifier.
func (k *KeyShare) Algorithm() tss.Algorithm {
	return tss.AlgorithmCGGMP21Secp256k1
}

// PartyID returns the owner party of this key share.
func (k *KeyShare) PartyID() tss.PartyID {
	if k == nil {
		return 0
	}
	return k.Party
}

// PublicKeyBytes returns a copy of the group secp256k1 public key.
func (k *KeyShare) PublicKeyBytes() []byte {
	if k == nil {
		return nil
	}
	return slices.Clone(k.PublicKey)
}

// DerivePublicKey applies a secp256k1 additive scalar shift to publicKey.
func DerivePublicKey(publicKey, additiveShift []byte) ([]byte, error) {
	base, err := secp.PointFromBytes(publicKey)
	if err != nil {
		return nil, err
	}
	if len(additiveShift) == 0 {
		return secp.PointBytes(base)
	}
	shift, err := secp.ParseScalar(additiveShift)
	if err != nil {
		return nil, fmt.Errorf("invalid additive shift: %w", err)
	}
	return secp.PointBytes(secp.Add(base, secp.ScalarBaseMult(shift)))
}

// MarshalBinary encodes the share using canonical TLV wire format.
func (k *KeyShare) MarshalBinary() ([]byte, error) {
	return marshalKeyShare(k)
}

// UnmarshalKeyShare decodes a canonical CGGMP21 key-share record.
func UnmarshalKeyShare(in []byte) (*KeyShare, error) {
	return unmarshalKeyShare(in)
}

// Validate checks share structure and canonical secp256k1/Paillier material.
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
	if err := validateStrictSortedParties(k.Parties); err != nil {
		return err
	}
	if !tss.ContainsParty(k.Parties, k.Party) {
		return errors.New("key share party is not in participant set")
	}
	if _, err := secp.PointFromBytes(k.PublicKey); err != nil {
		return fmt.Errorf("invalid group public key: %w", err)
	}
	if len(k.ChainCode) != 0 && len(k.ChainCode) != 32 {
		return errors.New("chain code must be 32 bytes")
	}
	if _, err := secp.ParseScalar(k.Secret); err != nil {
		return fmt.Errorf("invalid secret scalar: %w", err)
	}
	if len(k.GroupCommitments) != k.Threshold {
		return errors.New("group commitments length must equal threshold")
	}
	for i, commitment := range k.GroupCommitments {
		if _, err := secp.PointFromBytes(commitment); err != nil {
			return fmt.Errorf("invalid group commitment %d: %w", i, err)
		}
	}
	if len(k.VerificationShares) != len(k.Parties) {
		return errors.New("verification share count must equal party count")
	}
	seen := make(map[tss.PartyID]struct{}, len(k.VerificationShares))
	for i, vs := range k.VerificationShares {
		if vs.Party != k.Parties[i] {
			return errors.New("verification shares must follow party order")
		}
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
	if len(k.PaillierPublicKeys) > 0 {
		if len(k.PaillierPublicKeys) != len(k.Parties) {
			return errors.New("paillier public key count must equal party count")
		}
		for i, item := range k.PaillierPublicKeys {
			if item.Party != k.Parties[i] {
				return errors.New("paillier public keys must follow party order")
			}
			if len(item.PublicKey) == 0 || len(item.Proof) == 0 {
				return fmt.Errorf("incomplete paillier public key for party %d", item.Party)
			}
			if _, err := pai.UnmarshalPublicKey(item.PublicKey); err != nil {
				return fmt.Errorf("invalid paillier public key for party %d: %w", item.Party, err)
			}
		}
	}
	if len(k.PaillierPublicKey) > 0 {
		if _, err := pai.UnmarshalPublicKey(k.PaillierPublicKey); err != nil {
			return fmt.Errorf("invalid paillier public key: %w", err)
		}
	}
	if len(k.PaillierPrivateKey) > 0 {
		sk, err := pai.UnmarshalPrivateKey(k.PaillierPrivateKey)
		if err != nil {
			return fmt.Errorf("invalid paillier private key: %w", err)
		}
		pub, err := sk.PublicKey.MarshalBinary()
		if err != nil {
			return err
		}
		if len(k.PaillierPublicKey) > 0 && !bytes.Equal(pub, k.PaillierPublicKey) {
			return errors.New("paillier public/private key mismatch")
		}
	}
	return nil
}

// Destroy zeros local secret scalar and Paillier private-key bytes in place.
func (k *KeyShare) Destroy() {
	if k == nil {
		return
	}
	clear(k.Secret)
	clear(k.PaillierPrivateKey)
}

func (k *KeyShare) secretBig() (*big.Int, error) {
	return secp.ParseScalar(k.Secret)
}

func scalarBytes(x *big.Int) []byte {
	return secp.ScalarBytes(x)
}

func (k *KeyShare) requireMPCMaterial() error {
	if err := k.Validate(); err != nil {
		return err
	}
	if len(k.PaillierPublicKey) == 0 || len(k.PaillierPrivateKey) == 0 || len(k.PaillierProof) == 0 || len(k.ShareProof) == 0 || len(k.KeygenTranscriptHash) == 0 {
		return errors.New("secp256k1 key share is missing Paillier/ZK material; rerun keygen")
	}
	pk, err := k.paillierPublic()
	if err != nil {
		return err
	}
	if _, err := k.paillierPrivate(); err != nil {
		return err
	}
	modProof, err := zkpai.UnmarshalModulusProof(k.PaillierProof)
	if err != nil {
		return err
	}
	if !zkpai.VerifyModulus(k.KeygenTranscriptHash, pk, uint32(k.Party), modProof) {
		return errors.New("invalid local Paillier proof")
	}
	shareProof := new(schnorr.Proof)
	if err := json.Unmarshal(k.ShareProof, shareProof); err != nil {
		return fmt.Errorf("invalid share proof: %w", err)
	}
	verificationShare, ok := k.verificationShare(k.Party)
	if !ok {
		return errors.New("missing local verification share")
	}
	if !schnorr.Verify(k.KeygenTranscriptHash, verificationShare, shareProof) {
		return errors.New("invalid local share proof")
	}
	for _, id := range k.Parties {
		if _, err := k.paillierPublicFor(id); err != nil {
			return err
		}
	}
	return nil
}

func (k *KeyShare) paillierPublic() (*pai.PublicKey, error) {
	return pai.UnmarshalPublicKey(k.PaillierPublicKey)
}

func (k *KeyShare) paillierPrivate() (*pai.PrivateKey, error) {
	return pai.UnmarshalPrivateKey(k.PaillierPrivateKey)
}

func (k *KeyShare) paillierPublicFor(id tss.PartyID) (*pai.PublicKey, error) {
	if id == k.Party {
		return k.paillierPublic()
	}
	for _, item := range k.PaillierPublicKeys {
		if item.Party == id {
			return pai.UnmarshalPublicKey(item.PublicKey)
		}
	}
	return nil, fmt.Errorf("missing Paillier public key for party %d", id)
}

func (k *KeyShare) verificationShare(id tss.PartyID) ([]byte, bool) {
	for _, share := range k.VerificationShares {
		if share.Party == id {
			return share.PublicKey, true
		}
	}
	return nil, false
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
