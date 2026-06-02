package secp256k1

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"slices"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/wire"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
	"github.com/islishude/tss/internal/zk/schnorr"
)

const protocol = "cggmp21-secp256k1"

const (
	payloadKeygenCommitments  = "cggmp21.secp256k1.keygen.commitments"
	payloadKeygenShare        = "cggmp21.secp256k1.keygen.share"
	payloadPresignRound1      = "cggmp21.secp256k1.presign.round1"
	payloadPresignRound2      = "cggmp21.secp256k1.presign.round2"
	payloadPresignRound3      = "cggmp21.secp256k1.presign.round3"
	payloadSignPartial        = "cggmp21.secp256k1.sign.partial"
	payloadRefreshCommitments = "cggmp21.secp256k1.refresh.commitments"
	payloadRefreshShare       = "cggmp21.secp256k1.refresh.share"
)

// DefaultPaillierBits is the production default Paillier modulus size.
const DefaultPaillierBits = 2048

// defaultPaillierBits is the active default, overridable in tests.
var defaultPaillierBits = DefaultPaillierBits

// SetDefaultPaillierBitsForTesting overrides the default Paillier modulus size
// and returns a function that restores the previous value.
func SetDefaultPaillierBitsForTesting(bits int) func() {
	old := defaultPaillierBits
	defaultPaillierBits = bits
	return func() { defaultPaillierBits = old }
}

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
	Version                 uint16        `json:"version"`
	Party                   tss.PartyID   `json:"party"`
	Threshold               int           `json:"threshold"`
	Parties                 []tss.PartyID `json:"parties"`
	PublicKey               []byte        `json:"public_key"`
	ChainCode               []byte        `json:"chain_code,omitempty"`
	secret                  []byte
	GroupCommitments        [][]byte            `json:"group_commitments"`
	VerificationShares      []VerificationShare `json:"verification_shares"`
	PaillierPublicKey       []byte              `json:"paillier_public_key,omitempty"`
	paillierPrivateKey      []byte
	PaillierProof           []byte                `json:"paillier_proof,omitempty"`
	PaillierPrimalityProof  []byte                `json:"paillier_primality_proof,omitempty"`
	PaillierPrimalityProofs [][]byte              `json:"paillier_primality_proofs,omitempty"`
	PaillierPublicKeys      []PaillierPublicShare `json:"paillier_public_keys,omitempty"`
	PaillierProofSessionID  tss.SessionID         `json:"paillier_proof_session_id"`
	PaillierProofDomain     string                `json:"paillier_proof_domain"`
	ShareProof              []byte                `json:"share_proof,omitempty"`
	KeygenTranscriptHash    []byte                `json:"keygen_transcript_hash,omitempty"`
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

// MarshalJSON rejects default JSON encoding of secret-bearing key shares.
func (k KeyShare) MarshalJSON() ([]byte, error) {
	return nil, errors.New("cggmp21 secp256k1 key share contains secret material; use MarshalBinary")
}

// String returns a redacted representation of the key share.
func (k KeyShare) String() string {
	return k.redactedString()
}

// GoString returns a redacted representation of the key share.
func (k KeyShare) GoString() string {
	return k.redactedString()
}

// Format writes a redacted representation of the key share.
func (k *KeyShare) Format(state fmt.State, verb rune) {
	if k == nil {
		_, _ = fmt.Fprint(state, "<nil>")
		return
	}
	_, _ = fmt.Fprint(state, k.redactedString())
}

func (k KeyShare) redactedString() string {
	return fmt.Sprintf(
		"KeyShare{Version:%d Party:%d Threshold:%d Parties:%v PublicKey:%x ChainCode:%d bytes Secret:<redacted> GroupCommitments:%d VerificationShares:%d PaillierPublicKey:%d bytes PaillierPrivateKey:<redacted> PaillierProof:%d bytes PaillierPrimalityProof:%d bytes PaillierPrimalityProofs:%d PaillierPublicKeys:%d PaillierProofSessionID:%s PaillierProofDomain:%q ShareProof:%d bytes KeygenTranscriptHash:%x}",
		k.Version,
		k.Party,
		k.Threshold,
		k.Parties,
		k.PublicKey,
		len(k.ChainCode),
		len(k.GroupCommitments),
		len(k.VerificationShares),
		len(k.PaillierPublicKey),
		len(k.PaillierProof),
		len(k.PaillierPrimalityProof),
		len(k.PaillierPrimalityProofs),
		len(k.PaillierPublicKeys),
		k.PaillierProofSessionID,
		k.PaillierProofDomain,
		len(k.ShareProof),
		k.KeygenTranscriptHash,
	)
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
	if err := wire.ValidateStrictSortedIDs(k.Parties); err != nil {
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
	if _, err := secp.ParseScalar(k.secret); err != nil {
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
	if len(k.PaillierPublicKey) == 0 {
		return errors.New("missing paillier public key")
	}
	if len(k.paillierPrivateKey) == 0 {
		return errors.New("missing paillier private key")
	}
	if len(k.PaillierProof) == 0 {
		return errors.New("missing paillier proof")
	}
	if len(k.PaillierPrimalityProof) == 0 {
		return errors.New("missing paillier primality proof")
	}
	if len(k.PaillierPublicKeys) != len(k.Parties) {
		return errors.New("paillier public key count must equal party count")
	}
	if k.PaillierProofDomain == "" {
		return errors.New("missing paillier public proof domain")
	}
	if len(k.ShareProof) == 0 {
		return errors.New("missing share proof")
	}
	if len(k.KeygenTranscriptHash) == 0 {
		return errors.New("missing keygen transcript hash")
	}
	pk, err := pai.UnmarshalPublicKey(k.PaillierPublicKey)
	if err != nil {
		return fmt.Errorf("invalid paillier public key: %w", err)
	}
	sk, err := pai.UnmarshalPrivateKey(k.paillierPrivateKey)
	if err != nil {
		return fmt.Errorf("invalid paillier private key: %w", err)
	}
	pub, err := sk.PublicKey.MarshalBinary()
	if err != nil {
		return err
	}
	if !bytes.Equal(pub, k.PaillierPublicKey) {
		return errors.New("paillier public/private key mismatch")
	}
	modProof, err := zkpai.UnmarshalModulusProof(k.PaillierProof)
	if err != nil {
		return fmt.Errorf("invalid paillier proof: %w", err)
	}
	if !zkpai.VerifyModulus(keySharePaillierProofDomain(k), pk, uint32(k.Party), modProof) {
		return errors.New("invalid local paillier proof")
	}
	if len(k.PaillierPrimalityProofs) != len(k.Parties) {
		return errors.New("paillier primality proof count must equal party count")
	}
	for i, item := range k.PaillierPublicKeys {
		if item.Party != k.Parties[i] {
			return errors.New("paillier public keys must follow party order")
		}
		if len(item.PublicKey) == 0 || len(item.Proof) == 0 {
			return fmt.Errorf("incomplete paillier public key for party %d", item.Party)
		}
		peerPK, err := pai.UnmarshalPublicKey(item.PublicKey)
		if err != nil {
			return fmt.Errorf("invalid paillier public key for party %d: %w", item.Party, err)
		}
		peerProof, err := zkpai.UnmarshalModulusProof(item.Proof)
		if err != nil {
			return fmt.Errorf("invalid paillier proof for party %d: %w", item.Party, err)
		}
		// Verify the modulus proof is internally consistent with the public key.
		if peerProof.NBits != peerPK.N.BitLen() {
			return fmt.Errorf("paillier proof bit length mismatch for party %d: proof claims %d bits, key has %d bits", item.Party, peerProof.NBits, peerPK.N.BitLen())
		}
		proofDomain, err := k.paillierPublicProofDomainFor(item.Party, item.PublicKey)
		if err != nil {
			return err
		}
		if !zkpai.VerifyModulus(proofDomain, peerPK, uint32(item.Party), peerProof) {
			return fmt.Errorf("invalid paillier proof for party %d", item.Party)
		}
		if len(k.PaillierPrimalityProofs[i]) == 0 {
			return fmt.Errorf("missing paillier primality proof for party %d", item.Party)
		}
		peerPrimalityProof, err := zkpai.UnmarshalPrimalityProof(k.PaillierPrimalityProofs[i])
		if err != nil {
			return fmt.Errorf("invalid paillier primality proof for party %d: %w", item.Party, err)
		}
		if peerPrimalityProof.FactorBitLen < peerPK.N.BitLen()/2-1 || peerPrimalityProof.FactorBitLen > peerPK.N.BitLen()/2+1 {
			return fmt.Errorf("paillier primality proof factor bit length mismatch for party %d: proof claims %d bits, key has %d bits", item.Party, peerPrimalityProof.FactorBitLen, peerPK.N.BitLen())
		}
		if !zkpai.VerifyPrimality(proofDomain, peerPK, uint32(item.Party), peerPrimalityProof) {
			return fmt.Errorf("invalid paillier primality proof for party %d", item.Party)
		}
	}
	shareProof, err := schnorr.UnmarshalProof(k.ShareProof)
	if err != nil {
		return fmt.Errorf("invalid share proof: %w", err)
	}
	verificationShare, ok := k.verificationShare(k.Party)
	if !ok {
		return errors.New("missing local verification share")
	}
	if !schnorr.Verify(k.KeygenTranscriptHash, verificationShare, shareProof) {
		return errors.New("invalid local share proof")
	}
	return nil
}

func (k *KeyShare) paillierPublicProofDomainFor(party tss.PartyID, paillierPublicKey []byte) ([]byte, error) {
	config := tss.ThresholdConfig{
		Threshold: k.Threshold,
		Parties:   k.Parties,
		Self:      party,
		SessionID: k.PaillierProofSessionID,
	}
	switch k.PaillierProofDomain {
	case domainLabelKeygenModulus:
		return keygenModulusDomain(config, party, paillierPublicKey), nil
	case domainLabelRefreshPaillier:
		return refreshPaillierDomain(config, party, paillierPublicKey), nil
	case domainLabelResharePaillier:
		return resharePaillierDomain(config, party, paillierPublicKey), nil
	default:
		return nil, fmt.Errorf("unsupported paillier public proof domain %q", k.PaillierProofDomain)
	}
}

// sortedPaillierPrimalityProofs collects primality proofs in party order.
func sortedPaillierPrimalityProofs(parties []tss.PartyID, proofs map[tss.PartyID][]byte) [][]byte {
	out := make([][]byte, 0, len(parties))
	for _, id := range parties {
		out = append(out, append([]byte(nil), proofs[id]...))
	}
	return out
}

// Destroy zeros local secret scalar and Paillier private-key bytes in place.
func (k *KeyShare) Destroy() {
	if k == nil {
		return
	}
	clear(k.ChainCode)
	clear(k.secret)
	clear(k.paillierPrivateKey)
}

func (k *KeyShare) secretBig() (*big.Int, error) {
	s, err := secp.ParseScalar(k.secret)
	if err != nil {
		return nil, err
	}
	return s.BigInt(), nil
}

func scalarBytes(x *big.Int) []byte {
	return secp.ScalarBytes(secp.ScalarFromBigInt(x))
}

func (k *KeyShare) requireMPCMaterial() error {
	if err := k.Validate(); err != nil {
		return err
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
	return pai.UnmarshalPrivateKey(k.paillierPrivateKey)
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

func cloneKeyShareValue(k *KeyShare) *KeyShare {
	if k == nil {
		return nil
	}
	out := *k
	out.Parties = slices.Clone(k.Parties)
	out.PublicKey = slices.Clone(k.PublicKey)
	out.ChainCode = slices.Clone(k.ChainCode)
	out.secret = slices.Clone(k.secret)
	out.GroupCommitments = cloneKeyShareByteSlices(k.GroupCommitments)
	out.VerificationShares = cloneVerificationShares(k.VerificationShares)
	out.PaillierPublicKey = slices.Clone(k.PaillierPublicKey)
	out.paillierPrivateKey = slices.Clone(k.paillierPrivateKey)
	out.PaillierProof = slices.Clone(k.PaillierProof)
	out.PaillierPrimalityProof = slices.Clone(k.PaillierPrimalityProof)
	out.PaillierPrimalityProofs = cloneKeyShareByteSlices(k.PaillierPrimalityProofs)
	out.PaillierPublicKeys = clonePaillierPublicShares(k.PaillierPublicKeys)
	out.ShareProof = slices.Clone(k.ShareProof)
	out.KeygenTranscriptHash = slices.Clone(k.KeygenTranscriptHash)
	return &out
}

func cloneKeyShareByteSlices(in [][]byte) [][]byte {
	if in == nil {
		return nil
	}
	out := make([][]byte, len(in))
	for i, item := range in {
		out[i] = slices.Clone(item)
	}
	return out
}

func cloneVerificationShares(in []VerificationShare) []VerificationShare {
	if in == nil {
		return nil
	}
	out := slices.Clone(in)
	for i := range out {
		out[i].PublicKey = slices.Clone(out[i].PublicKey)
	}
	return out
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

func requireDirectConfidential(env tss.Envelope, self tss.PartyID, payloadType string) error {
	if env.To != self {
		return fmt.Errorf("%s must be addressed to receiver", payloadType)
	}
	if !env.ConfidentialRequired {
		return fmt.Errorf("%s must require confidential transport", payloadType)
	}
	return nil
}
