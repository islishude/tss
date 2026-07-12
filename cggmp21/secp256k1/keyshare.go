package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"slices"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/bip32util"
	"github.com/islishude/tss/internal/wire"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
	"github.com/islishude/tss/internal/zk/schnorr"
)

// Algorithm returns the common algorithm identifier.
func (k *KeyShare) Algorithm() tss.Algorithm {
	return tss.AlgorithmCGGMP21Secp256k1
}

// PartyID returns the owner party of this key share.
func (k *KeyShare) PartyID() tss.PartyID {
	if k == nil || k.state == nil {
		return 0
	}
	return k.state.Party
}

// Threshold returns the signing threshold.
func (k *KeyShare) Threshold() int {
	if k == nil || k.state == nil {
		return 0
	}
	return k.state.Threshold
}

// PublicMetadata returns a caller-owned snapshot of non-secret key-share
// metadata that is not scoped to a single participant.
func (k *KeyShare) PublicMetadata() (KeySharePublicMetadata, bool) {
	if k == nil || k.state == nil {
		return KeySharePublicMetadata{}, false
	}
	groupCommitments, err := secp.CommitmentPointsBytes(k.state.GroupCommitments)
	if err != nil {
		return KeySharePublicMetadata{}, false
	}
	shareProof, err := proofWireBytes(k.state.ShareProof)
	if err != nil {
		return KeySharePublicMetadata{}, false
	}
	logCiphertext, err := bigIntWireBytes(k.state.LogCiphertext)
	if err != nil {
		return KeySharePublicMetadata{}, false
	}
	logProof, err := proofWireBytes(k.state.LogProof)
	if err != nil {
		return KeySharePublicMetadata{}, false
	}
	return KeySharePublicMetadata{
		SecurityParams:       k.state.SecurityParams,
		Party:                k.state.Party,
		Threshold:            k.state.Threshold,
		Parties:              k.state.Parties.Clone(),
		PublicKey:            bytes.Clone(k.state.PublicKey),
		ChainCode:            bytes.Clone(k.state.ChainCode),
		GroupCommitments:     groupCommitments,
		PaillierProofSession: k.state.PaillierProofSessionID,
		PaillierProofDomain:  k.state.PaillierProofDomain,
		ResharePlanHash:      bytes.Clone(k.state.ResharePlanHash),
		PlanHash:             bytes.Clone(k.state.PlanHash),
		ShareProof:           shareProof,
		KeygenTranscriptHash: bytes.Clone(k.state.KeygenTranscriptHash),
		LogCiphertext:        logCiphertext,
		LogProof:             logProof,
	}, true
}

// Derive resolves a non-hardened BIP32 derivation path from this key share.
func (k *KeyShare) Derive(path tss.DerivationPath, opts ...tss.DeriveOption) (*tss.DerivationResult, error) {
	if k == nil || k.state == nil {
		return nil, errors.New("nil key share")
	}
	return DeriveNonHardenedBIP32(k.state.PublicKey, k.state.ChainCode, path.Clone(), opts...)
}

// VerificationShare returns a caller-owned public verification share for party.
func (k *KeyShare) VerificationShare(party tss.PartyID) (VerificationShare, bool) {
	data, err := k.partyDataFor(party)
	if err != nil || len(data.VerificationShare) == 0 {
		return VerificationShare{}, false
	}
	return VerificationShare{Party: party, PublicKey: bytes.Clone(data.VerificationShare)}, true
}

// PaillierPublicShare returns a caller-owned Paillier public-key snapshot for party.
func (k *KeyShare) PaillierPublicShare(party tss.PartyID) (PaillierPublicShare, bool) {
	data, err := k.partyDataFor(party)
	if err != nil || data.PaillierPublicKey == nil || data.PaillierProof == nil {
		return PaillierPublicShare{}, false
	}
	publicKey, err := canonicalWireMessageBytes(data.PaillierPublicKey, DefaultLimits())
	if err != nil {
		return PaillierPublicShare{}, false
	}
	proof, err := canonicalWireMessageBytes(data.PaillierProof, DefaultLimits())
	if err != nil {
		return PaillierPublicShare{}, false
	}
	return PaillierPublicShare{Party: party, PublicKey: publicKey, Proof: proof}, true
}

// RingPedersenPublicShare returns a caller-owned Ring-Pedersen snapshot for party.
func (k *KeyShare) RingPedersenPublicShare(party tss.PartyID) (RingPedersenPublicShare, bool) {
	data, err := k.partyDataFor(party)
	if err != nil || data.RingPedersenParams == nil || data.RingPedersenProof == nil {
		return RingPedersenPublicShare{}, false
	}
	params, err := canonicalWireMessageBytes(data.RingPedersenParams, DefaultLimits())
	if err != nil {
		return RingPedersenPublicShare{}, false
	}
	proof, err := canonicalWireMessageBytes(data.RingPedersenProof, DefaultLimits())
	if err != nil {
		return RingPedersenPublicShare{}, false
	}
	return RingPedersenPublicShare{Party: party, Params: params, Proof: proof}, true
}

// PaillierProofSessionID returns the session bound into the Paillier proof.
func (k *KeyShare) PaillierProofSessionID() tss.SessionID {
	if k == nil || k.state == nil {
		return tss.SessionID{}
	}
	return k.state.PaillierProofSessionID
}

// PaillierProofDomain returns the Paillier proof domain label.
func (k *KeyShare) PaillierProofDomain() string {
	if k == nil || k.state == nil {
		return ""
	}
	return k.state.PaillierProofDomain
}

// KeygenConfirmation returns a caller-owned keygen confirmation for party.
func (k *KeyShare) KeygenConfirmation(party tss.PartyID) (*KeygenConfirmation, bool) {
	data, err := k.partyDataFor(party)
	if err != nil || data.KeygenConfirmation == nil {
		return nil, false
	}
	return data.KeygenConfirmation.Clone(), true
}

// SecurityParams returns the cryptographic profile persisted with the share.
func (k *KeyShare) SecurityParams() SecurityParams {
	if k == nil || k.state == nil {
		return SecurityParams{}
	}
	return k.state.SecurityParams
}

// MarshalBinary encodes the share using canonical TLV wire format.
func (k *KeyShare) MarshalBinary() ([]byte, error) {
	return k.MarshalBinaryWithLimits(DefaultLimits())
}

// MarshalBinaryWithLimits encodes the share using explicit local limits.
func (k *KeyShare) MarshalBinaryWithLimits(limits Limits) ([]byte, error) {
	return k.marshalWireMessageWithLimits(limits)
}

// MarshalJSON rejects default JSON encoding of secret-bearing key shares.
// The value receiver ensures json.Marshal is blocked for both KeyShare and *KeyShare.
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
	if k == nil || k.state == nil {
		_, _ = fmt.Fprint(state, "<nil>")
		return
	}
	_, _ = fmt.Fprint(state, k.redactedString())
}

func (k KeyShare) redactedString() string {
	if k.state == nil {
		return "<nil>"
	}
	localData := k.state.PartyData[k.state.Party]
	confirmationCount := 0
	for _, data := range k.state.PartyData {
		if data.KeygenConfirmation != nil {
			confirmationCount++
		}
	}
	return fmt.Sprintf(
		"KeyShare{Party:%d Threshold:%d Parties:%v PublicKey:%x ChainCode:%d bytes Secret:<redacted> GroupCommitments:%d PartyData:%d PaillierPublicKey:%d bytes PaillierPrivateKey:<redacted> PaillierProof:%d bytes RingPedersenParams:%d bytes RingPedersenProof:%d bytes PaillierProofSessionID:%s PaillierProofDomain:%q ResharePlanHash:%d bytes PlanHash:%d bytes ShareProof:%d bytes KeygenTranscriptHash:%x LogCiphertext:%d bytes LogProof:%d bytes KeygenConfirmations:%d}",

		k.state.Party,
		k.state.Threshold,
		k.state.Parties,
		k.state.PublicKey,
		len(k.state.ChainCode),
		len(k.state.GroupCommitments),
		len(k.state.PartyData),
		wireMessageSize(localData.PaillierPublicKey),
		wireMessageSize(localData.PaillierProof),
		wireMessageSize(localData.RingPedersenParams),
		wireMessageSize(localData.RingPedersenProof),
		k.state.PaillierProofSessionID,
		k.state.PaillierProofDomain,
		len(k.state.ResharePlanHash),
		len(k.state.PlanHash),
		proofWireSize(k.state.ShareProof),
		k.state.KeygenTranscriptHash,
		bigIntWireSize(k.state.LogCiphertext),
		proofWireSize(k.state.LogProof),
		confirmationCount,
	)
}

func wireMessageSize(msg wire.Message) int {
	if msg == nil {
		return 0
	}
	raw, err := canonicalWireMessageBytes(msg, DefaultLimits())
	if err != nil {
		return 0
	}
	return len(raw)
}

func proofWireBytes(proof wire.ValueMarshaler) ([]byte, error) {
	if proof == nil {
		return nil, nil
	}
	switch p := any(proof).(type) {
	case *schnorr.Proof:
		if p == nil {
			return nil, nil
		}
	case *zkpai.LogStarProof:
		if p == nil {
			return nil, nil
		}
	}
	return proof.MarshalWireValue()
}

func proofWireSize(proof wire.ValueMarshaler) int {
	raw, err := proofWireBytes(proof)
	if err != nil {
		return 0
	}
	return len(raw)
}

func bigIntWireSize(x *big.Int) int {
	raw, err := bigIntWireBytes(x)
	if err != nil {
		return 0
	}
	return len(raw)
}

func bigIntWireBytes(x *big.Int) ([]byte, error) {
	if x == nil {
		return nil, nil
	}
	return wire.EncodeBigPos(x)
}

func cloneCommitmentPoints(in []*secp.Point) []*secp.Point {
	if in == nil {
		return nil
	}
	out := make([]*secp.Point, len(in))
	for i, commitment := range in {
		if commitment == nil {
			continue
		}
		out[i] = secp.Clone(commitment)
	}
	return out
}

// UnmarshalBinary decodes a canonical CGGMP21 key-share record with size caps.
func (k *KeyShare) UnmarshalBinary(in []byte) error {
	return k.UnmarshalBinaryWithLimits(in, DefaultLimits())
}

// UnmarshalBinaryWithLimits decodes a canonical key-share record into the
// receiver using explicit local resource limits.
func (k *KeyShare) UnmarshalBinaryWithLimits(in []byte, limits Limits) error {
	if len(in) == 0 {
		return errors.New("empty key share")
	}
	if len(in) > limits.State.MaxSerializedKeyShareBytes {
		return fmt.Errorf("key share too large: %d > %d", len(in), limits.State.MaxSerializedKeyShareBytes)
	}
	var decoded KeyShare
	if err := decoded.unmarshalWireMessageWithLimits(in, limits,
		wire.WithFrameLimits(limits.frameLimits(limits.State.MaxSerializedKeyShareBytes)),
	); err != nil {
		return err
	}
	k.state = decoded.state
	return nil
}

func (k *KeyShare) validateWithoutConfirmations(limits Limits) error {
	if k == nil || k.state == nil {
		return errors.New("nil key share")
	}
	if err := k.state.SecurityParams.Validate(); err != nil {
		return fmt.Errorf("invalid security params: %w", err)
	}
	if k.state.Threshold <= 0 || k.state.Threshold > len(k.state.Parties) {
		return errors.New("invalid threshold")
	}
	if err := wire.ValidateStrictSortedIDs(k.state.Parties); err != nil {
		return err
	}
	if !tss.ContainsParty(k.state.Parties, k.state.Party) {
		return errors.New("key share party is not in participant set")
	}
	if k.state.PartyData == nil {
		return errors.New("missing party data")
	}
	if err := k.state.checkPartyDataKeys(); err != nil {
		return err
	}
	if _, err := secp.PointFromBytes(k.state.PublicKey); err != nil {
		return fmt.Errorf("invalid group public key: %w", err)
	}
	if len(k.state.ChainCode) != bip32util.ChainCodeSize {
		return fmt.Errorf("chain code must be %d bytes", bip32util.ChainCodeSize)
	}
	if _, err := secpScalarFromSecret(k.state.Secret); err != nil {
		return fmt.Errorf("invalid secret scalar: %w", err)
	}
	if len(k.state.GroupCommitments) != k.state.Threshold {
		return errors.New("group commitments length must equal threshold")
	}
	for i, commitment := range k.state.GroupCommitments {
		if commitment == nil {
			if i == 0 {
				return errors.New("missing group commitment 0")
			}
			continue
		}
		if _, err := secp.PointBytes(commitment); err != nil {
			return fmt.Errorf("invalid group commitment %d: %w", i, err)
		}
	}
	if k.state.PaillierPrivateKey == nil {
		return errors.New("missing paillier private key")
	}
	if k.state.PaillierProofDomain == "" {
		return errors.New("missing paillier public proof domain")
	}
	if len(k.state.PlanHash) != sha256.Size {
		return errors.New("missing lifecycle plan hash")
	}
	if k.state.PaillierProofDomain == domainLabelResharePaillier {
		if len(k.state.ResharePlanHash) != sha256.Size {
			return errors.New("missing reshare plan hash")
		}
		if !bytes.Equal(k.state.ResharePlanHash, k.state.PlanHash) {
			return errors.New("reshare plan hash does not match lifecycle plan hash")
		}
	} else if len(k.state.ResharePlanHash) != 0 {
		return errors.New("reshare plan hash is only valid for reshare key shares")
	}
	if k.state.ShareProof == nil {
		return errors.New("missing share proof")
	}
	if len(k.state.KeygenTranscriptHash) == 0 {
		return errors.New("missing keygen transcript hash")
	}
	if k.state.LogCiphertext == nil {
		return errors.New("missing log ciphertext")
	}
	if k.state.LogProof == nil {
		return errors.New("missing log proof")
	}
	for _, id := range k.state.Parties {
		data := k.state.PartyData[id]
		if len(data.VerificationShare) == 0 {
			return fmt.Errorf("missing verification share for party %d", id)
		}
		if _, err := secp.PointFromBytes(data.VerificationShare); err != nil {
			return fmt.Errorf("invalid verification share for %d: %w", id, err)
		}
		if data.PaillierPublicKey == nil || data.PaillierProof == nil {
			return fmt.Errorf("incomplete paillier public key for party %d", id)
		}
		if data.RingPedersenParams == nil || data.RingPedersenProof == nil {
			return fmt.Errorf("incomplete Ring-Pedersen public parameters for party %d", id)
		}
		peerPK := data.PaillierPublicKey
		if err := peerPK.Validate(); err != nil {
			return fmt.Errorf("invalid paillier public key for party %d: %w", id, err)
		}
		if err := checkPaillierModulusBounds(peerPK, limits, k.state.SecurityParams); err != nil {
			return fmt.Errorf("paillier modulus for party %d does not meet security requirements: %w", id, err)
		}
		peerProof := data.PaillierProof
		if err := peerProof.Validate(); err != nil {
			return fmt.Errorf("invalid paillier proof for party %d: %w", id, err)
		}
		var proofDomain []byte
		var err error
		if id == k.state.Party {
			proofDomain, err = keySharePaillierProofDomain(k, limits)
		} else {
			proofDomain, err = k.paillierPublicProofDomainFor(id, peerPK, limits)
		}
		if err != nil {
			return err
		}
		if !zkpai.VerifyModulus(proofDomain, peerPK, id, peerProof) {
			return fmt.Errorf("invalid paillier proof for party %d", id)
		}
		peerRPParams := data.RingPedersenParams
		if err := peerRPParams.Validate(); err != nil {
			return fmt.Errorf("invalid Ring-Pedersen parameters for party %d: %w", id, err)
		}
		if peerRPParams.N.Cmp(peerPK.N) != 0 {
			return fmt.Errorf("Ring-Pedersen modulus mismatch for party %d", id)
		}
		peerRPProof := data.RingPedersenProof
		if err := peerRPProof.Validate(); err != nil {
			return fmt.Errorf("invalid Ring-Pedersen proof for party %d: %w", id, err)
		}
		rpDomain, err := keyShareRingPedersenProofDomain(k, id, peerRPParams, limits)
		if err != nil {
			return err
		}
		if !zkpai.VerifyRingPedersen(k.state.SecurityParams, rpDomain, peerRPParams, id, peerRPProof) {
			return fmt.Errorf("invalid Ring-Pedersen proof for party %d", id)
		}
	}
	localData := k.state.PartyData[k.state.Party]
	pk := localData.PaillierPublicKey
	sk := k.state.PaillierPrivateKey
	if err := sk.Validate(); err != nil {
		return fmt.Errorf("invalid paillier private key: %w", err)
	}
	if sk.N.Cmp(pk.N) != 0 || sk.G.Cmp(pk.G) != 0 || sk.NSquared.Cmp(pk.NSquared) != 0 {
		return errors.New("paillier public/private key mismatch")
	}
	verificationShare, ok := k.verificationShare(k.state.Party)
	if !ok {
		return errors.New("missing local verification share")
	}
	secretScalar, err := secpScalarFromSecret(k.state.Secret)
	if err != nil {
		return fmt.Errorf("invalid secret scalar: %w", err)
	}
	verificationPoint, err := secp.PointFromBytes(verificationShare)
	if err != nil {
		return fmt.Errorf("invalid verification share: %w", err)
	}
	if !secp.Equal(secp.ScalarBaseMult(secretScalar), verificationPoint) {
		return errors.New("local secret scalar does not match verification share")
	}
	if !schnorr.Verify(k.state.KeygenTranscriptHash, verificationShare, k.state.ShareProof) {
		return errors.New("invalid local share proof")
	}
	if err := pk.ValidateCiphertext(k.state.LogCiphertext); err != nil {
		return fmt.Errorf("invalid log ciphertext: %w", err)
	}
	rp, err := k.ringPedersenPublicFor(k.state.Party, limits)
	if err != nil {
		return fmt.Errorf("missing RP params for log proof: %w", err)
	}
	logDomain, err := logProofDomain(k, pk, verificationShare, k.state.KeygenTranscriptHash, limits)
	if err != nil {
		return err
	}
	logStmt := zkpai.LogStarStatement{
		PaillierN:   pk,
		C:           new(big.Int).Set(k.state.LogCiphertext),
		X:           verificationPoint,
		B:           secp.ScalarBaseMult(secp.ScalarFromBigInt(big.NewInt(1))),
		VerifierAux: rp,
	}
	if err := zkpai.VerifyLogStar(k.state.SecurityParams, logDomain, logStmt, k.state.LogProof); err != nil {
		return fmt.Errorf("invalid log proof: %w", err)
	}
	return nil
}

// Validate checks share structure, canonical secp256k1/Paillier material, and
// the complete keygen confirmation evidence set against production limits.
func (k *KeyShare) Validate() error {
	if k == nil || k.state == nil {
		return errors.New("nil key share")
	}
	if !isProductionSecurityParams(k.state.SecurityParams) {
		return errors.New("key share uses non-production security params")
	}
	return k.ValidateWithLimits(DefaultLimits())
}

// ValidateWithLimits checks share structure, canonical secp256k1/Paillier material,
// and the complete keygen confirmation evidence set against the provided Limits.
// It enforces hard caps on party count and threshold, and rejects configurations
// below the production minimum threshold unless explicitly allowed by the limits.
func (k *KeyShare) ValidateWithLimits(limits Limits) error {
	if err := k.validateResourceLimits(limits); err != nil {
		return err
	}
	if err := k.validateWithoutConfirmations(limits); err != nil {
		return err
	}
	if err := limits.Threshold.ValidateThreshold(k.state.Threshold, len(k.state.Parties)); err != nil {
		return err
	}
	confirmations, err := k.orderedKeygenConfirmations()
	if err != nil {
		return err
	}
	// Chain code enforcement: during keygen, each party commits to an
	// individual chain code that XORs to the aggregate. Refresh and reshare
	// preserve an existing aggregate chain code, so every confirmation must
	// repeat exactly that preserved value.
	if k.state.PaillierProofDomain == domainLabelRefreshPaillier || k.state.PaillierProofDomain == domainLabelResharePaillier {
		if err := verifyKeygenConfirmationSetPreservedChainCodeStruct(k, confirmations); err != nil {
			return fmt.Errorf("invalid keygen confirmations: %w", err)
		}
	} else {
		if err := verifyKeygenConfirmationSetBinding(k, confirmations); err != nil {
			return fmt.Errorf("invalid keygen confirmations: %w", err)
		}
	}
	return nil
}

func (k *KeyShare) validateResourceLimits(limits Limits) error {
	if k == nil || k.state == nil {
		return errors.New("nil key share")
	}
	if len(k.state.Parties) > limits.Threshold.MaxParties {
		return fmt.Errorf("too many parties: %d > %d", len(k.state.Parties), limits.Threshold.MaxParties)
	}
	if k.state.Threshold > limits.Threshold.MaxThreshold {
		return fmt.Errorf("threshold too large: %d > %d", k.state.Threshold, limits.Threshold.MaxThreshold)
	}
	if len(k.state.GroupCommitments) > limits.Threshold.MaxThreshold {
		return fmt.Errorf("group commitments too large: %d > %d", len(k.state.GroupCommitments), limits.Threshold.MaxThreshold)
	}
	for i, commitment := range k.state.GroupCommitments {
		if commitment == nil {
			continue
		}
		commitmentBytes, err := secp.PointBytes(commitment)
		if err != nil {
			return fmt.Errorf("group commitment %d: %w", i, err)
		}
		if len(commitmentBytes) > limits.Curve.MaxPointBytes {
			return fmt.Errorf("group commitment %d too large: %d > %d", i, len(commitmentBytes), limits.Curve.MaxPointBytes)
		}
	}
	if len(k.state.PartyData) > limits.Threshold.MaxParties {
		return fmt.Errorf("party data too large: %d > %d", len(k.state.PartyData), limits.Threshold.MaxParties)
	}
	if k.state.PaillierPrivateKey == nil {
		return errors.New("missing paillier private key")
	}
	paillierPrivateKeyBytes, err := k.state.PaillierPrivateKey.MarshalBinary()
	if err != nil {
		return fmt.Errorf("paillier private key: %w", err)
	}
	if len(paillierPrivateKeyBytes) > limits.Paillier.MaxPrivateKeyBytes {
		return fmt.Errorf("paillier private key too large: %d > %d", len(paillierPrivateKeyBytes), limits.Paillier.MaxPrivateKeyBytes)
	}
	for _, id := range k.state.Parties {
		data, ok := k.state.PartyData[id]
		if !ok {
			return fmt.Errorf("missing party data for participant %d", id)
		}
		if len(data.VerificationShare) > limits.Curve.MaxPointBytes {
			return fmt.Errorf("verification share for party %d too large: %d > %d", id, len(data.VerificationShare), limits.Curve.MaxPointBytes)
		}
		paillierPublicKeyBytes, err := canonicalWireMessageBytes(data.PaillierPublicKey, limits)
		if err != nil {
			return fmt.Errorf("paillier public key for party %d: %w", id, err)
		}
		if len(paillierPublicKeyBytes) > limits.Paillier.MaxPublicKeyBytes {
			return fmt.Errorf("paillier public key for party %d too large: %d > %d", id, len(paillierPublicKeyBytes), limits.Paillier.MaxPublicKeyBytes)
		}
		paillierProofBytes, err := canonicalWireMessageBytes(data.PaillierProof, limits)
		if err != nil {
			return fmt.Errorf("paillier proof for party %d: %w", id, err)
		}
		if len(paillierProofBytes) > limits.ZK.MaxProofBytes {
			return fmt.Errorf("paillier proof for party %d too large: %d > %d", id, len(paillierProofBytes), limits.ZK.MaxProofBytes)
		}
		ringPedersenParamsBytes, err := canonicalWireMessageBytes(data.RingPedersenParams, limits)
		if err != nil {
			return fmt.Errorf("Ring-Pedersen parameters for party %d: %w", id, err)
		}
		if len(ringPedersenParamsBytes) > limits.Paillier.MaxRingPedersenBytes {
			return fmt.Errorf("Ring-Pedersen parameters for party %d too large: %d > %d", id, len(ringPedersenParamsBytes), limits.Paillier.MaxRingPedersenBytes)
		}
		ringPedersenProofBytes, err := canonicalWireMessageBytes(data.RingPedersenProof, limits)
		if err != nil {
			return fmt.Errorf("Ring-Pedersen proof for party %d: %w", id, err)
		}
		if len(ringPedersenProofBytes) > limits.Paillier.MaxProofBytes {
			return fmt.Errorf("Ring-Pedersen proof for party %d too large: %d > %d", id, len(ringPedersenProofBytes), limits.Paillier.MaxProofBytes)
		}
	}
	if k.state.ShareProof != nil {
		shareProofBytes, err := proofWireBytes(k.state.ShareProof)
		if err != nil {
			return fmt.Errorf("share proof: %w", err)
		}
		if len(shareProofBytes) > limits.ZK.MaxProofBytes {
			return fmt.Errorf("share proof too large: %d > %d", len(shareProofBytes), limits.ZK.MaxProofBytes)
		}
	}
	if k.state.LogCiphertext != nil {
		logCiphertextBytes, err := wire.EncodeBigPos(k.state.LogCiphertext)
		if err != nil {
			return fmt.Errorf("log ciphertext: %w", err)
		}
		if len(logCiphertextBytes) > limits.Paillier.MaxCiphertextBytes {
			return fmt.Errorf("log ciphertext too large: %d > %d", len(logCiphertextBytes), limits.Paillier.MaxCiphertextBytes)
		}
	}
	if k.state.LogProof != nil {
		logProofBytes, err := proofWireBytes(k.state.LogProof)
		if err != nil {
			return fmt.Errorf("log proof: %w", err)
		}
		if len(logProofBytes) > limits.ZK.MaxProofBytes {
			return fmt.Errorf("log proof too large: %d > %d", len(logProofBytes), limits.ZK.MaxProofBytes)
		}
	}
	confirmationCount := 0
	for _, data := range k.state.PartyData {
		if data.KeygenConfirmation != nil {
			confirmationCount++
		}
	}
	if confirmationCount > limits.Threshold.MaxParties {
		return fmt.Errorf("keygen confirmations too large: %d > %d", confirmationCount, limits.Threshold.MaxParties)
	}
	return nil
}

func (k *KeyShare) paillierPublicProofDomainFor(party tss.PartyID, paillierPublicKey *pai.PublicKey, limits Limits) ([]byte, error) {
	config := tss.ThresholdConfig{
		Threshold: k.state.Threshold,
		Parties:   k.state.Parties,
		Self:      party,
		SessionID: k.state.PaillierProofSessionID,
	}
	switch k.state.PaillierProofDomain {
	case domainLabelKeygenModulus:
		return keygenModulusDomain(config, party, paillierPublicKey, k.state.PlanHash, limits)
	case domainLabelRefreshPaillier:
		return refreshPaillierDomain(config, party, paillierPublicKey, k.state.PlanHash, limits)
	case domainLabelResharePaillier:
		return resharePaillierDomain(config, party, paillierPublicKey, k.state.PlanHash, limits)
	default:
		return nil, fmt.Errorf("unsupported paillier public proof domain %q", k.state.PaillierProofDomain)
	}
}

func checkPaillierModulusBounds(pk *pai.PublicKey, limits Limits, params SecurityParams) error {
	if pk == nil || pk.N == nil {
		return errors.New("nil paillier public key")
	}
	if limits.Paillier.MaxModulusBits > 0 && pk.N.BitLen() > limits.Paillier.MaxModulusBits {
		return fmt.Errorf("paillier modulus has %d bits, max %d", pk.N.BitLen(), limits.Paillier.MaxModulusBits)
	}
	return params.CheckPaillierModulus(pk)
}

// Destroy zeros the local secret scalar, Paillier private key, and chain
// code in place. After Destroy, the KeyShare is permanently unusable for MPC
// operations.
//
// # Go zeroization boundaries
//
// Destroy zeroes the fields that this package controls: secret (fixed-length
// [secret.Scalar]), paillierPrivateKey (Paillier lambda/mu), and ChainCode. It does
// not zero GroupCommitments, VerificationShares, or other public material —
// those fields contain no secret data. The Paillier private key that has been
// not zero public protocol material. A shallow Go copy is only another handle to
// this same lifecycle state. Callers that extracted values via getters (for
// example [KeyShare.ChainCodeBytes]) before Destroy own independent copies that
// must be zeroed separately.
func (k *KeyShare) Destroy() {
	if k == nil || k.state == nil {
		return
	}
	clear(k.state.ChainCode)
	if k.state.Secret != nil {
		k.state.Secret.Destroy()
	}
	if k.state.PaillierPrivateKey != nil {
		k.state.PaillierPrivateKey.Destroy()
	}
}

func (k *KeyShare) requireMPCMaterial(limits Limits) error {
	if err := k.ValidateWithLimits(limits); err != nil {
		return err
	}
	for _, id := range k.state.Parties {
		if _, err := k.paillierPublicFor(id, limits); err != nil {
			return err
		}
	}
	return nil
}

func (k *KeyShare) partyDataFor(id tss.PartyID) (keySharePartyData, error) {
	if k == nil || k.state == nil {
		return keySharePartyData{}, errors.New("nil key share")
	}
	if !tss.ContainsParty(k.state.Parties, id) {
		return keySharePartyData{}, fmt.Errorf("party %d is not a participant", id)
	}
	data, ok := k.state.PartyData[id]
	if !ok {
		return keySharePartyData{}, fmt.Errorf("missing party data for participant %d", id)
	}
	return data, nil
}

func (k *KeyShare) orderedKeygenConfirmations() ([]*KeygenConfirmation, error) {
	if k == nil || k.state == nil {
		return nil, errors.New("nil key share")
	}
	out := make([]*KeygenConfirmation, 0, len(k.state.Parties))
	for _, id := range k.state.Parties {
		data, ok := k.state.PartyData[id]
		if !ok {
			return nil, fmt.Errorf("missing party data for participant %d", id)
		}
		if data.KeygenConfirmation == nil {
			return nil, fmt.Errorf("missing keygen confirmation for party %d", id)
		}
		if data.KeygenConfirmation.Sender != id {
			return nil, fmt.Errorf("keygen confirmation sender %d does not match party data key %d", data.KeygenConfirmation.Sender, id)
		}
		out = append(out, data.KeygenConfirmation.Clone())
	}
	return out, nil
}

func (k *KeyShare) paillierPublic(limits Limits) (*pai.PublicKey, error) {
	data, err := k.partyDataFor(k.state.Party)
	if err != nil {
		return nil, err
	}
	if data.PaillierPublicKey == nil {
		return nil, errors.New("missing local Paillier public key")
	}
	if err := checkPaillierModulusBounds(data.PaillierPublicKey, limits, k.state.SecurityParams); err != nil {
		return nil, err
	}
	return data.PaillierPublicKey.Clone(), nil
}

func (k *KeyShare) paillierPrivate() (*pai.PrivateKey, error) {
	if k.state.PaillierPrivateKey == nil {
		return nil, errors.New("missing local Paillier private key")
	}
	if err := k.state.PaillierPrivateKey.Validate(); err != nil {
		return nil, fmt.Errorf("invalid local Paillier private key: %w", err)
	}
	return k.state.PaillierPrivateKey.Clone(), nil
}

func (k *KeyShare) paillierPublicFor(id tss.PartyID, limits Limits) (*pai.PublicKey, error) {
	data, err := k.partyDataFor(id)
	if err != nil {
		return nil, err
	}
	if data.PaillierPublicKey == nil {
		return nil, fmt.Errorf("missing Paillier public key for party %d", id)
	}
	if err := checkPaillierModulusBounds(data.PaillierPublicKey, limits, k.state.SecurityParams); err != nil {
		return nil, err
	}
	return data.PaillierPublicKey.Clone(), nil
}

func (k *KeyShare) paillierPublicShares(limits Limits) ([]PaillierPublicShare, error) {
	if k == nil || k.state == nil {
		return nil, errors.New("nil key share")
	}
	out := make([]PaillierPublicShare, 0, len(k.state.Parties))
	for _, id := range k.state.Parties {
		data, err := k.partyDataFor(id)
		if err != nil {
			return nil, err
		}
		publicKey, err := canonicalWireMessageBytes(data.PaillierPublicKey, limits)
		if err != nil {
			return nil, err
		}
		proof, err := canonicalWireMessageBytes(data.PaillierProof, limits)
		if err != nil {
			return nil, err
		}
		out = append(out, PaillierPublicShare{Party: id, PublicKey: publicKey, Proof: proof})
	}
	return out, nil
}

// ringPedersenPublicFor returns the Ring-Pedersen parameters for a given party.
func (k *KeyShare) ringPedersenPublicFor(id tss.PartyID, _ Limits) (*zkpai.RingPedersenParams, error) {
	data, err := k.partyDataFor(id)
	if err != nil {
		return nil, err
	}
	if data.RingPedersenParams == nil {
		return nil, fmt.Errorf("missing Ring-Pedersen params for party %d", id)
	}
	return data.RingPedersenParams.Clone(), nil
}

func (k *KeyShare) verificationShare(id tss.PartyID) ([]byte, bool) {
	data, err := k.partyDataFor(id)
	if err != nil || len(data.VerificationShare) == 0 {
		return nil, false
	}
	return data.VerificationShare, true
}

func cloneKeyShareValue(k *KeyShare) *KeyShare {
	if k == nil || k.state == nil {
		return nil
	}
	return &KeyShare{state: &keyShareState{
		SecurityParams:         k.state.SecurityParams,
		Party:                  k.state.Party,
		Threshold:              k.state.Threshold,
		Parties:                slices.Clone(k.state.Parties),
		PublicKey:              slices.Clone(k.state.PublicKey),
		ChainCode:              slices.Clone(k.state.ChainCode),
		Secret:                 k.state.Secret.Clone(),
		GroupCommitments:       cloneCommitmentPoints(k.state.GroupCommitments),
		PartyData:              tss.CloneMap(k.state.PartyData),
		PaillierPrivateKey:     k.state.PaillierPrivateKey.Clone(),
		PaillierProofSessionID: k.state.PaillierProofSessionID,
		PaillierProofDomain:    k.state.PaillierProofDomain,
		ResharePlanHash:        slices.Clone(k.state.ResharePlanHash),
		PlanHash:               slices.Clone(k.state.PlanHash),
		ShareProof:             k.state.ShareProof.Clone(),
		KeygenTranscriptHash:   slices.Clone(k.state.KeygenTranscriptHash),
		LogCiphertext:          tss.CloneBigInt(k.state.LogCiphertext),
		LogProof:               k.state.LogProof.Clone(),
	}}
}
