package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"slices"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/wire"
	"github.com/islishude/tss/internal/wire/wireutil"

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
	return k.state.party
}

// Threshold returns the signing threshold.
func (k *KeyShare) Threshold() int {
	if k == nil || k.state == nil {
		return 0
	}
	return k.state.threshold
}

// Parties returns a copy of the canonical participant set.
func (k *KeyShare) Parties() tss.PartySet {
	if k == nil || k.state == nil {
		return nil
	}
	return slices.Clone(k.state.parties)
}

// PublicKeyBytes returns a copy of the group secp256k1 public key.
func (k *KeyShare) PublicKeyBytes() []byte {
	if k == nil || k.state == nil {
		return nil
	}
	return slices.Clone(k.state.publicKey)
}

// ChainCodeBytes returns a copy of the HD chain code. The chain code is
// cleared by [KeyShare.Destroy]; callers that need the value after Destroy
// must capture it first.
func (k *KeyShare) ChainCodeBytes() []byte {
	if k == nil || k.state == nil {
		return nil
	}
	return slices.Clone(k.state.chainCode)
}

// Derive resolves a non-hardened BIP32 derivation path from this key share.
func (k *KeyShare) Derive(path tss.DerivationPath, opts ...tss.DeriveOption) (*tss.DerivationResult, error) {
	if k == nil || k.state == nil {
		return nil, errors.New("nil key share")
	}
	return DeriveNonHardenedBIP32Extended(k.state.publicKey, k.state.chainCode, path.Clone(), opts...)
}

// GroupCommitments returns a deep copy of the per-degree group commitments.
func (k *KeyShare) GroupCommitments() [][]byte {
	if k == nil || k.state == nil {
		return nil
	}
	return wireutil.CloneByteSlices(k.state.groupCommitments)
}

// VerificationShares returns a deep copy of the participant verification shares.
func (k *KeyShare) VerificationShares() []VerificationShare {
	if k == nil || k.state == nil {
		return nil
	}
	out := make([]VerificationShare, 0, len(k.state.parties))
	for _, id := range k.state.parties {
		data, ok := k.state.partyData[id]
		if !ok {
			return nil
		}
		out = append(out, VerificationShare{Party: id, PublicKey: bytes.Clone(data.verificationShare)})
	}
	return out
}

// PaillierPublicKeyBytes returns a copy of the local Paillier public key.
func (k *KeyShare) PaillierPublicKeyBytes() []byte {
	data, err := k.partyDataFor(k.PartyID())
	if err != nil || data.paillierPublicKey == nil {
		return nil
	}
	raw, err := canonicalWireMessageBytes(data.paillierPublicKey, DefaultLimits())
	if err != nil {
		return nil
	}
	return raw
}

// PaillierProofBytes returns a copy of the local Paillier modulus proof.
func (k *KeyShare) PaillierProofBytes() []byte {
	data, err := k.partyDataFor(k.PartyID())
	if err != nil || data.paillierProof == nil {
		return nil
	}
	raw, err := canonicalWireMessageBytes(data.paillierProof, DefaultLimits())
	if err != nil {
		return nil
	}
	return raw
}

// PaillierPublicKeys returns deep copies of all participant Paillier public keys.
func (k *KeyShare) PaillierPublicKeys() []PaillierPublicShare {
	if k == nil || k.state == nil {
		return nil
	}
	out := make([]PaillierPublicShare, 0, len(k.state.parties))
	for _, id := range k.state.parties {
		data, ok := k.state.partyData[id]
		if !ok {
			return nil
		}
		publicKey, err := canonicalWireMessageBytes(data.paillierPublicKey, DefaultLimits())
		if err != nil {
			return nil
		}
		proof, err := canonicalWireMessageBytes(data.paillierProof, DefaultLimits())
		if err != nil {
			return nil
		}
		out = append(out, PaillierPublicShare{Party: id, PublicKey: publicKey, Proof: proof})
	}
	return out
}

// RingPedersenParamsBytes returns a copy of the local Ring-Pedersen parameters.
func (k *KeyShare) RingPedersenParamsBytes() []byte {
	data, err := k.partyDataFor(k.PartyID())
	if err != nil || data.ringPedersenParams == nil {
		return nil
	}
	raw, err := canonicalWireMessageBytes(data.ringPedersenParams, DefaultLimits())
	if err != nil {
		return nil
	}
	return raw
}

// RingPedersenProofBytes returns a copy of the local Ring-Pedersen proof.
func (k *KeyShare) RingPedersenProofBytes() []byte {
	data, err := k.partyDataFor(k.PartyID())
	if err != nil || data.ringPedersenProof == nil {
		return nil
	}
	raw, err := canonicalWireMessageBytes(data.ringPedersenProof, DefaultLimits())
	if err != nil {
		return nil
	}
	return raw
}

// RingPedersenPublic returns deep copies of all public Ring-Pedersen records.
func (k *KeyShare) RingPedersenPublic() []RingPedersenPublicShare {
	if k == nil || k.state == nil {
		return nil
	}
	out := make([]RingPedersenPublicShare, 0, len(k.state.parties))
	for _, id := range k.state.parties {
		data, ok := k.state.partyData[id]
		if !ok {
			return nil
		}
		params, err := canonicalWireMessageBytes(data.ringPedersenParams, DefaultLimits())
		if err != nil {
			return nil
		}
		proof, err := canonicalWireMessageBytes(data.ringPedersenProof, DefaultLimits())
		if err != nil {
			return nil
		}
		out = append(out, RingPedersenPublicShare{Party: id, Params: params, Proof: proof})
	}
	return out
}

// PaillierProofSessionID returns the session bound into the Paillier proof.
func (k *KeyShare) PaillierProofSessionID() tss.SessionID {
	if k == nil || k.state == nil {
		return tss.SessionID{}
	}
	return k.state.paillierProofSessionID
}

// PaillierProofDomain returns the Paillier proof domain label.
func (k *KeyShare) PaillierProofDomain() string {
	if k == nil || k.state == nil {
		return ""
	}
	return k.state.paillierProofDomain
}

// ResharePlanHashBytes returns a copy of the bound reshare-plan hash.
func (k *KeyShare) ResharePlanHashBytes() []byte {
	if k == nil || k.state == nil {
		return nil
	}
	return slices.Clone(k.state.resharePlanHash)
}

// PlanHashBytes returns a copy of the lifecycle plan hash that produced this
// key share.
func (k *KeyShare) PlanHashBytes() []byte {
	if k == nil || k.state == nil {
		return nil
	}
	return slices.Clone(k.state.planHash)
}

// ShareProofBytes returns a copy of the Schnorr share-proof encoding.
func (k *KeyShare) ShareProofBytes() []byte {
	if k == nil || k.state == nil {
		return nil
	}
	return slices.Clone(k.state.shareProof)
}

// KeygenTranscriptHashBytes returns a copy of the keygen transcript hash.
func (k *KeyShare) KeygenTranscriptHashBytes() []byte {
	if k == nil || k.state == nil {
		return nil
	}
	return slices.Clone(k.state.keygenTranscriptHash)
}

// LogCiphertextBytes returns a copy of the local proof ciphertext.
func (k *KeyShare) LogCiphertextBytes() []byte {
	if k == nil || k.state == nil {
		return nil
	}
	return slices.Clone(k.state.logCiphertext)
}

// LogProofBytes returns a copy of the local logarithm proof.
func (k *KeyShare) LogProofBytes() []byte {
	if k == nil || k.state == nil {
		return nil
	}
	return slices.Clone(k.state.logProof)
}

// KeygenConfirmations returns a deep copy of the keygen confirmation set.
func (k *KeyShare) KeygenConfirmations() []*KeygenConfirmation {
	if k == nil || k.state == nil {
		return nil
	}
	confirmations, err := k.orderedKeygenConfirmations()
	if err != nil {
		return nil
	}
	return confirmations
}

// SecurityParams returns the cryptographic profile persisted with the share.
func (k *KeyShare) SecurityParams() SecurityParams {
	if k == nil || k.state == nil {
		return SecurityParams{}
	}
	return k.state.securityParams
}

// MarshalBinary encodes the share using canonical TLV wire format.
func (k *KeyShare) MarshalBinary() ([]byte, error) {
	return k.MarshalBinaryWithLimits(DefaultLimits())
}

// MarshalBinaryWithLimits encodes the share using explicit local limits.
func (k *KeyShare) MarshalBinaryWithLimits(limits Limits) ([]byte, error) {
	if err := k.ValidateWithLimits(limits); err != nil {
		return nil, err
	}
	return k.MarshalWireMessage(wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
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
	localData := k.state.partyData[k.state.party]
	confirmationCount := 0
	for _, data := range k.state.partyData {
		if data.keygenConfirmation != nil {
			confirmationCount++
		}
	}
	return fmt.Sprintf(
		"KeyShare{Party:%d Threshold:%d Parties:%v PublicKey:%x ChainCode:%d bytes Secret:<redacted> GroupCommitments:%d PartyData:%d PaillierPublicKey:%d bytes PaillierPrivateKey:<redacted> PaillierProof:%d bytes RingPedersenParams:%d bytes RingPedersenProof:%d bytes PaillierProofSessionID:%s PaillierProofDomain:%q ResharePlanHash:%d bytes PlanHash:%d bytes ShareProof:%d bytes KeygenTranscriptHash:%x LogCiphertext:%d bytes LogProof:%d bytes KeygenConfirmations:%d}",

		k.state.party,
		k.state.threshold,
		k.state.parties,
		k.state.publicKey,
		len(k.state.chainCode),
		len(k.state.groupCommitments),
		len(k.state.partyData),
		wireMessageSize(localData.paillierPublicKey),
		wireMessageSize(localData.paillierProof),
		wireMessageSize(localData.ringPedersenParams),
		wireMessageSize(localData.ringPedersenProof),
		k.state.paillierProofSessionID,
		k.state.paillierProofDomain,
		len(k.state.resharePlanHash),
		len(k.state.planHash),
		len(k.state.shareProof),
		k.state.keygenTranscriptHash,
		len(k.state.logCiphertext),
		len(k.state.logProof),
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

// UnmarshalKeyShare decodes a canonical CGGMP21 key-share record with size caps.
func UnmarshalKeyShare(in []byte) (*KeyShare, error) {
	return tss.DecodeBinary[KeyShare](in)
}

// UnmarshalKeyShareWithLimits decodes a canonical key-share record using
// explicit local resource limits.
func UnmarshalKeyShareWithLimits(in []byte, limits Limits) (*KeyShare, error) {
	return tss.DecodeBinaryWithLimits[KeyShare](in, limits)
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
	if err := decoded.UnmarshalWireMessage(in,
		wire.WithFrameLimits(limits.frameLimits(limits.State.MaxSerializedKeyShareBytes)),
		wire.WithFieldLimits(limits.fieldLimits()),
	); err != nil {
		return err
	}
	if err := decoded.ValidateWithLimits(limits); err != nil {
		return err
	}
	k.state = decoded.state
	return nil
}

func (k *KeyShare) validateWithoutConfirmations(limits Limits) error {
	if k == nil || k.state == nil {
		return errors.New("nil key share")
	}
	if err := k.state.securityParams.Validate(); err != nil {
		return fmt.Errorf("invalid security params: %w", err)
	}
	if k.state.threshold <= 0 || k.state.threshold > len(k.state.parties) {
		return errors.New("invalid threshold")
	}
	if err := wire.ValidateStrictSortedIDs(k.state.parties); err != nil {
		return err
	}
	if !tss.ContainsParty(k.state.parties, k.state.party) {
		return errors.New("key share party is not in participant set")
	}
	if k.state.partyData == nil {
		return errors.New("missing party data")
	}
	if len(k.state.partyData) != len(k.state.parties) {
		return fmt.Errorf("party data count %d != party count %d", len(k.state.partyData), len(k.state.parties))
	}
	for _, id := range k.state.parties {
		if id == tss.BroadcastPartyId {
			return errors.New("broadcast party cannot have key share party data")
		}
		if _, ok := k.state.partyData[id]; !ok {
			return fmt.Errorf("missing party data for participant %d", id)
		}
	}
	for id := range k.state.partyData {
		if id == tss.BroadcastPartyId {
			return errors.New("broadcast party cannot have key share party data")
		}
		if !tss.ContainsParty(k.state.parties, id) {
			return fmt.Errorf("party data for non-participant %d", id)
		}
	}
	if _, err := secp.PointFromBytes(k.state.publicKey); err != nil {
		return fmt.Errorf("invalid group public key: %w", err)
	}
	if len(k.state.chainCode) != 32 {
		return errors.New("chain code must be 32 bytes")
	}
	if _, err := secpScalarFromSecret(k.state.secret); err != nil {
		return fmt.Errorf("invalid secret scalar: %w", err)
	}
	if len(k.state.groupCommitments) != k.state.threshold {
		return errors.New("group commitments length must equal threshold")
	}
	for i, commitment := range k.state.groupCommitments {
		if _, err := secp.PointFromBytes(commitment); err != nil {
			return fmt.Errorf("invalid group commitment %d: %w", i, err)
		}
	}
	if k.state.paillierPrivateKey == nil {
		return errors.New("missing paillier private key")
	}
	if k.state.paillierProofDomain == "" {
		return errors.New("missing paillier public proof domain")
	}
	if len(k.state.planHash) != sha256.Size {
		return errors.New("missing lifecycle plan hash")
	}
	if k.state.paillierProofDomain == domainLabelResharePaillier {
		if len(k.state.resharePlanHash) != sha256.Size {
			return errors.New("missing reshare plan hash")
		}
		if !bytes.Equal(k.state.resharePlanHash, k.state.planHash) {
			return errors.New("reshare plan hash does not match lifecycle plan hash")
		}
	} else if len(k.state.resharePlanHash) != 0 {
		return errors.New("reshare plan hash is only valid for reshare key shares")
	}
	if len(k.state.shareProof) == 0 {
		return errors.New("missing share proof")
	}
	if len(k.state.keygenTranscriptHash) == 0 {
		return errors.New("missing keygen transcript hash")
	}
	if len(k.state.logCiphertext) == 0 {
		return errors.New("missing log ciphertext")
	}
	if len(k.state.logProof) == 0 {
		return errors.New("missing log proof")
	}
	for _, id := range k.state.parties {
		data := k.state.partyData[id]
		if len(data.verificationShare) == 0 {
			return fmt.Errorf("missing verification share for party %d", id)
		}
		if _, err := secp.PointFromBytes(data.verificationShare); err != nil {
			return fmt.Errorf("invalid verification share for %d: %w", id, err)
		}
		if data.paillierPublicKey == nil || data.paillierProof == nil {
			return fmt.Errorf("incomplete paillier public key for party %d", id)
		}
		if data.ringPedersenParams == nil || data.ringPedersenProof == nil {
			return fmt.Errorf("incomplete Ring-Pedersen public parameters for party %d", id)
		}
		peerPK := data.paillierPublicKey
		if err := peerPK.Validate(); err != nil {
			return fmt.Errorf("invalid paillier public key for party %d: %w", id, err)
		}
		if err := checkPaillierModulusBounds(peerPK, limits, k.state.securityParams); err != nil {
			return fmt.Errorf("paillier modulus for party %d does not meet security requirements: %w", id, err)
		}
		peerProof := data.paillierProof
		if err := peerProof.Validate(); err != nil {
			return fmt.Errorf("invalid paillier proof for party %d: %w", id, err)
		}
		var proofDomain []byte
		var err error
		if id == k.state.party {
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
		peerRPParams := data.ringPedersenParams
		if err := peerRPParams.Validate(); err != nil {
			return fmt.Errorf("invalid Ring-Pedersen parameters for party %d: %w", id, err)
		}
		if peerRPParams.N.Cmp(peerPK.N) != 0 {
			return fmt.Errorf("Ring-Pedersen modulus mismatch for party %d", id)
		}
		peerRPProof := data.ringPedersenProof
		if err := peerRPProof.Validate(); err != nil {
			return fmt.Errorf("invalid Ring-Pedersen proof for party %d: %w", id, err)
		}
		rpDomain, err := keyShareRingPedersenProofDomain(k, id, peerRPParams, limits)
		if err != nil {
			return err
		}
		if !zkpai.VerifyRingPedersen(rpDomain, peerRPParams, id, peerRPProof) {
			return fmt.Errorf("invalid Ring-Pedersen proof for party %d", id)
		}
	}
	localData := k.state.partyData[k.state.party]
	pk := localData.paillierPublicKey
	sk := k.state.paillierPrivateKey
	if err := sk.PublicKey.Validate(); err != nil {
		return fmt.Errorf("invalid paillier private key: %w", err)
	}
	if sk.N.Cmp(pk.N) != 0 || sk.G.Cmp(pk.G) != 0 || sk.NSquared.Cmp(pk.NSquared) != 0 {
		return errors.New("paillier public/private key mismatch")
	}
	shareProof, err := schnorr.UnmarshalProof(k.state.shareProof)
	if err != nil {
		return fmt.Errorf("invalid share proof: %w", err)
	}
	verificationShare, ok := k.verificationShare(k.state.party)
	if !ok {
		return errors.New("missing local verification share")
	}
	if !schnorr.Verify(k.state.keygenTranscriptHash, verificationShare, shareProof) {
		return errors.New("invalid local share proof")
	}
	logProof, err := zkpai.UnmarshalLogStarProof(k.state.logProof)
	if err != nil {
		return fmt.Errorf("invalid log proof: %w", err)
	}
	ciphertext := new(big.Int).SetBytes(k.state.logCiphertext)
	if err := pk.ValidateCiphertext(ciphertext); err != nil {
		return fmt.Errorf("invalid log ciphertext: %w", err)
	}
	rp, err := k.ringPedersenPublicFor(k.state.party, limits)
	if err != nil {
		return fmt.Errorf("missing RP params for log proof: %w", err)
	}
	verificationPoint, err := secp.PointFromBytes(verificationShare)
	if err != nil {
		return fmt.Errorf("invalid verification share: %w", err)
	}
	logDomain, err := logProofDomain(k, pk, verificationShare, k.state.keygenTranscriptHash, limits)
	if err != nil {
		return err
	}
	logStmt := zkpai.LogStarStatement{
		PaillierN:   pk,
		C:           ciphertext,
		X:           verificationPoint,
		B:           secp.ScalarBaseMult(secp.ScalarFromBigInt(big.NewInt(1))),
		VerifierAux: rp,
	}
	if err := zkpai.VerifyLogStar(k.state.securityParams, logDomain, logStmt, logProof); err != nil {
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
	if !isProductionSecurityParams(k.state.securityParams) {
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
	if err := limits.Threshold.ValidateThreshold(k.state.threshold, len(k.state.parties)); err != nil {
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
	if k.state.paillierProofDomain == domainLabelRefreshPaillier || k.state.paillierProofDomain == domainLabelResharePaillier {
		if err := verifyKeygenConfirmationSetPreservedChainCodeStruct(k, confirmations); err != nil {
			return fmt.Errorf("invalid keygen confirmations: %w", err)
		}
	} else {
		if err := verifyFinalizedKeygenConfirmationSet(k, confirmations); err != nil {
			return fmt.Errorf("invalid keygen confirmations: %w", err)
		}
	}
	return nil
}

func (k *KeyShare) validateResourceLimits(limits Limits) error {
	if k == nil || k.state == nil {
		return errors.New("nil key share")
	}
	if len(k.state.parties) > limits.Threshold.MaxParties {
		return fmt.Errorf("too many parties: %d > %d", len(k.state.parties), limits.Threshold.MaxParties)
	}
	if k.state.threshold > limits.Threshold.MaxThreshold {
		return fmt.Errorf("threshold too large: %d > %d", k.state.threshold, limits.Threshold.MaxThreshold)
	}
	if len(k.state.groupCommitments) > limits.Threshold.MaxThreshold {
		return fmt.Errorf("group commitments too large: %d > %d", len(k.state.groupCommitments), limits.Threshold.MaxThreshold)
	}
	for i, commitment := range k.state.groupCommitments {
		if len(commitment) > limits.Curve.MaxPointBytes {
			return fmt.Errorf("group commitment %d too large: %d > %d", i, len(commitment), limits.Curve.MaxPointBytes)
		}
	}
	if len(k.state.partyData) > limits.Threshold.MaxParties {
		return fmt.Errorf("party data too large: %d > %d", len(k.state.partyData), limits.Threshold.MaxParties)
	}
	if k.state.paillierPrivateKey == nil {
		return errors.New("missing paillier private key")
	}
	paillierPrivateKeyBytes, err := k.state.paillierPrivateKey.MarshalBinary()
	if err != nil {
		return fmt.Errorf("paillier private key: %w", err)
	}
	if len(paillierPrivateKeyBytes) > limits.Paillier.MaxPrivateKeyBytes {
		return fmt.Errorf("paillier private key too large: %d > %d", len(paillierPrivateKeyBytes), limits.Paillier.MaxPrivateKeyBytes)
	}
	for _, id := range k.state.parties {
		data, ok := k.state.partyData[id]
		if !ok {
			return fmt.Errorf("missing party data for participant %d", id)
		}
		if len(data.verificationShare) > limits.Curve.MaxPointBytes {
			return fmt.Errorf("verification share for party %d too large: %d > %d", id, len(data.verificationShare), limits.Curve.MaxPointBytes)
		}
		paillierPublicKeyBytes, err := canonicalWireMessageBytes(data.paillierPublicKey, limits)
		if err != nil {
			return fmt.Errorf("paillier public key for party %d: %w", id, err)
		}
		if len(paillierPublicKeyBytes) > limits.Paillier.MaxPublicKeyBytes {
			return fmt.Errorf("paillier public key for party %d too large: %d > %d", id, len(paillierPublicKeyBytes), limits.Paillier.MaxPublicKeyBytes)
		}
		paillierProofBytes, err := canonicalWireMessageBytes(data.paillierProof, limits)
		if err != nil {
			return fmt.Errorf("paillier proof for party %d: %w", id, err)
		}
		if len(paillierProofBytes) > limits.ZK.MaxProofBytes {
			return fmt.Errorf("paillier proof for party %d too large: %d > %d", id, len(paillierProofBytes), limits.ZK.MaxProofBytes)
		}
		ringPedersenParamsBytes, err := canonicalWireMessageBytes(data.ringPedersenParams, limits)
		if err != nil {
			return fmt.Errorf("Ring-Pedersen parameters for party %d: %w", id, err)
		}
		if len(ringPedersenParamsBytes) > limits.Paillier.MaxRingPedersenBytes {
			return fmt.Errorf("Ring-Pedersen parameters for party %d too large: %d > %d", id, len(ringPedersenParamsBytes), limits.Paillier.MaxRingPedersenBytes)
		}
		ringPedersenProofBytes, err := canonicalWireMessageBytes(data.ringPedersenProof, limits)
		if err != nil {
			return fmt.Errorf("Ring-Pedersen proof for party %d: %w", id, err)
		}
		if len(ringPedersenProofBytes) > limits.Paillier.MaxProofBytes {
			return fmt.Errorf("Ring-Pedersen proof for party %d too large: %d > %d", id, len(ringPedersenProofBytes), limits.Paillier.MaxProofBytes)
		}
	}
	if len(k.state.shareProof) > limits.ZK.MaxProofBytes {
		return fmt.Errorf("share proof too large: %d > %d", len(k.state.shareProof), limits.ZK.MaxProofBytes)
	}
	if len(k.state.logCiphertext) > limits.Paillier.MaxCiphertextBytes {
		return fmt.Errorf("log ciphertext too large: %d > %d", len(k.state.logCiphertext), limits.Paillier.MaxCiphertextBytes)
	}
	if len(k.state.logProof) > limits.ZK.MaxProofBytes {
		return fmt.Errorf("log proof too large: %d > %d", len(k.state.logProof), limits.ZK.MaxProofBytes)
	}
	confirmationCount := 0
	for _, data := range k.state.partyData {
		if data.keygenConfirmation != nil {
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
		Threshold: k.state.threshold,
		Parties:   k.state.parties,
		Self:      party,
		SessionID: k.state.paillierProofSessionID,
	}
	switch k.state.paillierProofDomain {
	case domainLabelKeygenModulus:
		return keygenModulusDomain(config, party, paillierPublicKey, k.state.planHash, limits)
	case domainLabelRefreshPaillier:
		return refreshPaillierDomain(config, party, paillierPublicKey, k.state.planHash, limits)
	case domainLabelResharePaillier:
		return resharePaillierDomain(config, party, paillierPublicKey, k.state.planHash, limits)
	default:
		return nil, fmt.Errorf("unsupported paillier public proof domain %q", k.state.paillierProofDomain)
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
	clear(k.state.chainCode)
	if k.state.secret != nil {
		k.state.secret.Destroy()
	}
	if k.state.paillierPrivateKey != nil {
		k.state.paillierPrivateKey.Destroy()
	}
}

func (k *KeyShare) requireMPCMaterial(limits Limits) error {
	if err := k.ValidateWithLimits(limits); err != nil {
		return err
	}
	for _, id := range k.state.parties {
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
	if !tss.ContainsParty(k.state.parties, id) {
		return keySharePartyData{}, fmt.Errorf("party %d is not a participant", id)
	}
	data, ok := k.state.partyData[id]
	if !ok {
		return keySharePartyData{}, fmt.Errorf("missing party data for participant %d", id)
	}
	return data, nil
}

func (k *KeyShare) orderedKeygenConfirmations() ([]*KeygenConfirmation, error) {
	if k == nil || k.state == nil {
		return nil, errors.New("nil key share")
	}
	out := make([]*KeygenConfirmation, 0, len(k.state.parties))
	for _, id := range k.state.parties {
		data, ok := k.state.partyData[id]
		if !ok {
			return nil, fmt.Errorf("missing party data for participant %d", id)
		}
		if data.keygenConfirmation == nil {
			return nil, fmt.Errorf("missing keygen confirmation for party %d", id)
		}
		if data.keygenConfirmation.Sender != id {
			return nil, fmt.Errorf("keygen confirmation sender %d does not match party data key %d", data.keygenConfirmation.Sender, id)
		}
		out = append(out, data.keygenConfirmation.Clone())
	}
	return out, nil
}

func (k *KeyShare) paillierPublic(limits Limits) (*pai.PublicKey, error) {
	data, err := k.partyDataFor(k.state.party)
	if err != nil {
		return nil, err
	}
	if data.paillierPublicKey == nil {
		return nil, errors.New("missing local Paillier public key")
	}
	if err := checkPaillierModulusBounds(data.paillierPublicKey, limits, k.state.securityParams); err != nil {
		return nil, err
	}
	return data.paillierPublicKey.Clone(), nil
}

func (k *KeyShare) paillierPrivate() (*pai.PrivateKey, error) {
	if k.state.paillierPrivateKey == nil {
		return nil, errors.New("missing local Paillier private key")
	}
	return k.state.paillierPrivateKey.Clone(), nil
}

func (k *KeyShare) paillierPublicFor(id tss.PartyID, limits Limits) (*pai.PublicKey, error) {
	data, err := k.partyDataFor(id)
	if err != nil {
		return nil, err
	}
	if data.paillierPublicKey == nil {
		return nil, fmt.Errorf("missing Paillier public key for party %d", id)
	}
	if err := checkPaillierModulusBounds(data.paillierPublicKey, limits, k.state.securityParams); err != nil {
		return nil, err
	}
	return data.paillierPublicKey.Clone(), nil
}

// ringPedersenPublicFor returns the Ring-Pedersen parameters for a given party.
func (k *KeyShare) ringPedersenPublicFor(id tss.PartyID, _ Limits) (zkpai.RingPedersenParams, error) {
	data, err := k.partyDataFor(id)
	if err != nil {
		return zkpai.RingPedersenParams{}, err
	}
	if data.ringPedersenParams == nil {
		return zkpai.RingPedersenParams{}, fmt.Errorf("missing Ring-Pedersen params for party %d", id)
	}
	return *data.ringPedersenParams.Clone(), nil
}

func (k *KeyShare) verificationShare(id tss.PartyID) ([]byte, bool) {
	data, err := k.partyDataFor(id)
	if err != nil || len(data.verificationShare) == 0 {
		return nil, false
	}
	return data.verificationShare, true
}

func cloneKeyShareValue(k *KeyShare) *KeyShare {
	if k == nil || k.state == nil {
		return nil
	}
	return &KeyShare{state: &keyShareState{
		securityParams:         k.state.securityParams,
		party:                  k.state.party,
		threshold:              k.state.threshold,
		parties:                slices.Clone(k.state.parties),
		publicKey:              slices.Clone(k.state.publicKey),
		chainCode:              slices.Clone(k.state.chainCode),
		secret:                 k.state.secret.Clone(),
		groupCommitments:       wireutil.CloneByteSlices(k.state.groupCommitments),
		partyData:              cloneKeySharePartyDataMap(k.state.partyData),
		paillierPrivateKey:     k.state.paillierPrivateKey.Clone(),
		paillierProofSessionID: k.state.paillierProofSessionID,
		paillierProofDomain:    k.state.paillierProofDomain,
		resharePlanHash:        slices.Clone(k.state.resharePlanHash),
		planHash:               slices.Clone(k.state.planHash),
		shareProof:             slices.Clone(k.state.shareProof),
		keygenTranscriptHash:   slices.Clone(k.state.keygenTranscriptHash),
		logCiphertext:          slices.Clone(k.state.logCiphertext),
		logProof:               slices.Clone(k.state.logProof),
	}}
}
