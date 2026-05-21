package secp256k1

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
	"github.com/islishude/tss/internal/zk/schnorr"
)

const protocol = "gg20-secp256k1"

const (
	payloadKeygenCommitments = "gg20.secp256k1.keygen.commitments"
	payloadKeygenShare       = "gg20.secp256k1.keygen.share"
	payloadPresignRound1     = "gg20.secp256k1.presign.round1"
	payloadPresignRound2     = "gg20.secp256k1.presign.round2"
	payloadPresignRound3     = "gg20.secp256k1.presign.round3"
	payloadSignPartial       = "gg20.secp256k1.sign.partial"
)

const ExperimentalSecurityNotice = "experimental GG20-style threshold ECDSA path: Paillier MtA is implemented with simplified proof coverage; independent audit required"

const DefaultPaillierBits = 2048

type VerificationShare struct {
	Party     tss.PartyID `json:"party"`
	PublicKey []byte      `json:"public_key"`
}

type PaillierPublicShare struct {
	Party     tss.PartyID `json:"party"`
	PublicKey []byte      `json:"public_key"`
	Proof     []byte      `json:"proof"`
}

type KeyShare struct {
	Version              uint16                `json:"version"`
	Party                tss.PartyID           `json:"party"`
	Threshold            int                   `json:"threshold"`
	Parties              []tss.PartyID         `json:"parties"`
	PublicKey            []byte                `json:"public_key"`
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

func (k *KeyShare) Destroy() {
	if k == nil {
		return
	}
	tss.SensitiveBytes(k.Secret).Destroy()
	tss.SensitiveBytes(k.PaillierPrivateKey).Destroy()
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
