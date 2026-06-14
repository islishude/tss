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

// Version returns the key-share wire version.
func (k *KeyShare) Version() uint16 {
	if k == nil || k.state == nil {
		return 0
	}
	return k.state.version
}

// Threshold returns the signing threshold.
func (k *KeyShare) Threshold() int {
	if k == nil || k.state == nil {
		return 0
	}
	return k.state.threshold
}

// Parties returns a copy of the canonical participant set.
func (k *KeyShare) Parties() []tss.PartyID {
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
	return cloneVerificationShares(k.state.verificationShares)
}

// PaillierPublicKeyBytes returns a copy of the local Paillier public key.
func (k *KeyShare) PaillierPublicKeyBytes() []byte {
	if k == nil || k.state == nil {
		return nil
	}
	return slices.Clone(k.state.paillierPublicKey)
}

// PaillierProofBytes returns a copy of the local Paillier modulus proof.
func (k *KeyShare) PaillierProofBytes() []byte {
	if k == nil || k.state == nil {
		return nil
	}
	return slices.Clone(k.state.paillierProof)
}

// PaillierPublicKeys returns deep copies of all participant Paillier public keys.
func (k *KeyShare) PaillierPublicKeys() []PaillierPublicShare {
	if k == nil || k.state == nil {
		return nil
	}
	return clonePaillierPublicShares(k.state.paillierPublicKeys)
}

// RingPedersenParamsBytes returns a copy of the local Ring-Pedersen parameters.
func (k *KeyShare) RingPedersenParamsBytes() []byte {
	if k == nil || k.state == nil {
		return nil
	}
	return slices.Clone(k.state.ringPedersenParams)
}

// RingPedersenProofBytes returns a copy of the local Ring-Pedersen proof.
func (k *KeyShare) RingPedersenProofBytes() []byte {
	if k == nil || k.state == nil {
		return nil
	}
	return slices.Clone(k.state.ringPedersenProof)
}

// RingPedersenPublic returns deep copies of all public Ring-Pedersen records.
func (k *KeyShare) RingPedersenPublic() []RingPedersenPublicShare {
	if k == nil || k.state == nil {
		return nil
	}
	return cloneRingPedersenPublicShares(k.state.ringPedersenPublic)
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
func (k *KeyShare) KeygenConfirmations() [][]byte {
	if k == nil || k.state == nil {
		return nil
	}
	return wireutil.CloneByteSlices(k.state.keygenConfirmations)
}

// MarshalBinary encodes the share using canonical TLV wire format.
func (k *KeyShare) MarshalBinary() ([]byte, error) {
	return marshalKeyShare(k)
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
	return fmt.Sprintf(
		"KeyShare{Version:%d Party:%d Threshold:%d Parties:%v PublicKey:%x ChainCode:%d bytes Secret:<redacted> GroupCommitments:%d VerificationShares:%d PaillierPublicKey:%d bytes PaillierPrivateKey:<redacted> PaillierProof:%d bytes PaillierPublicKeys:%d RingPedersenParams:%d bytes RingPedersenProof:%d bytes RingPedersenPublic:%d PaillierProofSessionID:%s PaillierProofDomain:%q ResharePlanHash:%d bytes PlanHash:%d bytes ShareProof:%d bytes KeygenTranscriptHash:%x LogCiphertext:%d bytes LogProof:%d bytes KeygenConfirmations:%d}",
		k.state.version,
		k.state.party,
		k.state.threshold,
		k.state.parties,
		k.state.publicKey,
		len(k.state.chainCode),
		len(k.state.groupCommitments),
		len(k.state.verificationShares),
		len(k.state.paillierPublicKey),
		len(k.state.paillierProof),
		len(k.state.paillierPublicKeys),
		len(k.state.ringPedersenParams),
		len(k.state.ringPedersenProof),
		len(k.state.ringPedersenPublic),
		k.state.paillierProofSessionID,
		k.state.paillierProofDomain,
		len(k.state.resharePlanHash),
		len(k.state.planHash),
		len(k.state.shareProof),
		k.state.keygenTranscriptHash,
		len(k.state.logCiphertext),
		len(k.state.logProof),
		len(k.state.keygenConfirmations),
	)
}

// UnmarshalKeyShare decodes a canonical CGGMP21 key-share record with size caps.
func UnmarshalKeyShare(in []byte) (*KeyShare, error) {
	limits := DefaultLimits()
	if len(in) == 0 {
		return nil, errors.New("empty key share")
	}
	if len(in) > limits.State.MaxSerializedKeyShareBytes {
		return nil, fmt.Errorf("key share too large: %d > %d", len(in), limits.State.MaxSerializedKeyShareBytes)
	}
	return unmarshalKeyShareWithLimits(in, limits)
}

func (k *KeyShare) validateWithoutConfirmations() error {
	if k == nil || k.state == nil {
		return errors.New("nil key share")
	}
	if k.state.version != tss.Version {
		return fmt.Errorf("unexpected key share version %d", k.state.version)
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
	if _, err := secp.PointFromBytes(k.state.publicKey); err != nil {
		return fmt.Errorf("invalid group public key: %w", err)
	}
	if len(k.state.chainCode) != 0 && len(k.state.chainCode) != 32 {
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
	if len(k.state.verificationShares) != len(k.state.parties) {
		return errors.New("verification share count must equal party count")
	}
	seen := make(map[tss.PartyID]struct{}, len(k.state.verificationShares))
	for i, vs := range k.state.verificationShares {
		if vs.Party != k.state.parties[i] {
			return errors.New("verification shares must follow party order")
		}
		if !tss.ContainsParty(k.state.parties, vs.Party) {
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
	if len(k.state.paillierPublicKey) == 0 {
		return errors.New("missing paillier public key")
	}
	if len(k.state.paillierPrivateKey) == 0 {
		return errors.New("missing paillier private key")
	}
	if len(k.state.paillierProof) == 0 {
		return errors.New("missing paillier proof")
	}
	if len(k.state.ringPedersenParams) == 0 {
		return errors.New("missing Ring-Pedersen parameters")
	}
	if len(k.state.ringPedersenProof) == 0 {
		return errors.New("missing Ring-Pedersen proof")
	}
	if len(k.state.paillierPublicKeys) != len(k.state.parties) {
		return errors.New("paillier public key count must equal party count")
	}
	if len(k.state.ringPedersenPublic) != len(k.state.parties) {
		return errors.New("Ring-Pedersen public parameter count must equal party count")
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
	limits := DefaultLimits()
	pk, err := pai.UnmarshalPublicKeyWithMaxModulusBits(k.state.paillierPublicKey, limits.Paillier.MaxModulusBits)
	if err != nil {
		return fmt.Errorf("invalid paillier public key: %w", err)
	}
	sk, err := pai.UnmarshalPrivateKey(k.state.paillierPrivateKey)
	if err != nil {
		return fmt.Errorf("invalid paillier private key: %w", err)
	}
	pub, err := sk.PublicKey.MarshalBinary()
	if err != nil {
		return err
	}
	if !bytes.Equal(pub, k.state.paillierPublicKey) {
		return errors.New("paillier public/private key mismatch")
	}
	modProof, err := zkpai.UnmarshalModulusProof(k.state.paillierProof)
	if err != nil {
		return fmt.Errorf("invalid paillier proof: %w", err)
	}
	if err := checkPaillierModulusBounds(pk, limits); err != nil {
		return fmt.Errorf("local paillier modulus does not meet security requirements: %w", err)
	}
	if !zkpai.VerifyModulus(keySharePaillierProofDomain(k), pk, uint32(k.state.party), modProof) {
		return errors.New("invalid local paillier proof")
	}
	localRPParams, err := zkpai.UnmarshalRingPedersenParamsWithMaxModulusBits(k.state.ringPedersenParams, limits.Paillier.MaxModulusBits)
	if err != nil {
		return fmt.Errorf("invalid local Ring-Pedersen parameters: %w", err)
	}
	if localRPParams.N.Cmp(pk.N) != 0 {
		return errors.New("local Ring-Pedersen modulus does not match Paillier modulus")
	}
	localRPProof, err := zkpai.UnmarshalRingPedersenProof(k.state.ringPedersenProof)
	if err != nil {
		return fmt.Errorf("invalid local Ring-Pedersen proof: %w", err)
	}
	localRPDomain := keyShareRingPedersenProofDomain(k, k.state.party, k.state.ringPedersenParams)
	if localRPDomain == nil {
		return fmt.Errorf("unsupported Ring-Pedersen proof domain %q", k.state.paillierProofDomain)
	}
	if !zkpai.VerifyRingPedersen(localRPDomain, localRPParams, uint32(k.state.party), localRPProof) {
		return errors.New("invalid local Ring-Pedersen proof")
	}
	for i, item := range k.state.paillierPublicKeys {
		if item.Party != k.state.parties[i] {
			return errors.New("paillier public keys must follow party order")
		}
		rp := k.state.ringPedersenPublic[i]
		if rp.Party != k.state.parties[i] {
			return errors.New("Ring-Pedersen public parameters must follow party order")
		}
		if rp.Party != item.Party {
			return fmt.Errorf("Ring-Pedersen public parameters do not match Paillier party %d", item.Party)
		}
		if len(item.PublicKey) == 0 || len(item.Proof) == 0 {
			return fmt.Errorf("incomplete paillier public key for party %d", item.Party)
		}
		if len(rp.Params) == 0 || len(rp.Proof) == 0 {
			return fmt.Errorf("incomplete Ring-Pedersen public parameters for party %d", rp.Party)
		}
		peerPK, err := pai.UnmarshalPublicKeyWithMaxModulusBits(item.PublicKey, limits.Paillier.MaxModulusBits)
		if err != nil {
			return fmt.Errorf("invalid paillier public key for party %d: %w", item.Party, err)
		}
		peerProof, err := zkpai.UnmarshalModulusProof(item.Proof)
		if err != nil {
			return fmt.Errorf("invalid paillier proof for party %d: %w", item.Party, err)
		}
		proofDomain, err := k.paillierPublicProofDomainFor(item.Party, item.PublicKey)
		if err != nil {
			return err
		}
		if err := checkPaillierModulusBounds(peerPK, limits); err != nil {
			return fmt.Errorf("paillier modulus for party %d does not meet security requirements: %w", item.Party, err)
		}
		if !zkpai.VerifyModulus(proofDomain, peerPK, uint32(item.Party), peerProof) {
			return fmt.Errorf("invalid paillier proof for party %d", item.Party)
		}
		peerRPParams, err := zkpai.UnmarshalRingPedersenParamsWithMaxModulusBits(rp.Params, limits.Paillier.MaxModulusBits)
		if err != nil {
			return fmt.Errorf("invalid Ring-Pedersen parameters for party %d: %w", rp.Party, err)
		}
		if peerRPParams.N.Cmp(peerPK.N) != 0 {
			return fmt.Errorf("Ring-Pedersen modulus mismatch for party %d", rp.Party)
		}
		peerRPProof, err := zkpai.UnmarshalRingPedersenProof(rp.Proof)
		if err != nil {
			return fmt.Errorf("invalid Ring-Pedersen proof for party %d: %w", rp.Party, err)
		}
		rpDomain := keyShareRingPedersenProofDomain(k, rp.Party, rp.Params)
		if rpDomain == nil {
			return fmt.Errorf("unsupported Ring-Pedersen proof domain %q", k.state.paillierProofDomain)
		}
		if !zkpai.VerifyRingPedersen(rpDomain, peerRPParams, uint32(rp.Party), peerRPProof) {
			return fmt.Errorf("invalid Ring-Pedersen proof for party %d", rp.Party)
		}
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
	rp, err := k.ringPedersenPublicFor(k.state.party)
	if err != nil {
		return fmt.Errorf("missing RP params for log proof: %w", err)
	}
	verificationPoint, err := secp.PointFromBytes(verificationShare)
	if err != nil {
		return fmt.Errorf("invalid verification share: %w", err)
	}
	logDomain := logProofDomain(k, pk, verificationShare, k.state.keygenTranscriptHash)
	logStmt := zkpai.LogStarStatement{
		PaillierN:   pk,
		C:           ciphertext,
		X:           verificationPoint,
		B:           secp.ScalarBaseMult(secp.ScalarFromBigInt(big.NewInt(1))),
		VerifierAux: rp,
	}
	if err := zkpai.VerifyLogStar(zkpai.ActiveSecurityParams(), logDomain, logStmt, logProof); err != nil {
		return fmt.Errorf("invalid log proof: %w", err)
	}
	return nil
}

// Validate checks share structure, canonical secp256k1/Paillier material, and
// the complete keygen confirmation evidence set against production limits.
func (k *KeyShare) Validate() error {
	return k.ValidateWithLimits(DefaultLimits())
}

// ValidateWithLimits checks share structure, canonical secp256k1/Paillier material,
// and the complete keygen confirmation evidence set against the provided Limits.
// It enforces hard caps on party count and threshold, and rejects configurations
// below the production minimum threshold unless explicitly allowed by the limits.
func (k *KeyShare) ValidateWithLimits(limits Limits) error {
	if err := k.validateWithoutConfirmations(); err != nil {
		return err
	}
	if len(k.state.parties) > limits.Threshold.MaxParties {
		return fmt.Errorf("too many parties: %d > %d", len(k.state.parties), limits.Threshold.MaxParties)
	}
	if k.state.threshold > limits.Threshold.MaxThreshold {
		return fmt.Errorf("threshold too large: %d > %d", k.state.threshold, limits.Threshold.MaxThreshold)
	}
	if err := limits.Threshold.ValidateThreshold(k.state.threshold, len(k.state.parties)); err != nil {
		return err
	}
	// Chain code enforcement: during keygen, each party commits to an
	// individual chain code that XORs to the aggregate. Refresh and reshare
	// preserve an existing aggregate chain code, so every confirmation must
	// repeat exactly that preserved value.
	if k.state.paillierProofDomain == domainLabelRefreshPaillier || k.state.paillierProofDomain == domainLabelResharePaillier {
		if err := verifyKeygenConfirmationSetPreservedChainCode(k, k.state.keygenConfirmations); err != nil {
			return fmt.Errorf("invalid keygen confirmations: %w", err)
		}
	} else {
		if err := verifyKeygenConfirmationSet(k, k.state.keygenConfirmations); err != nil {
			return fmt.Errorf("invalid keygen confirmations: %w", err)
		}
	}
	return nil
}

func (k *KeyShare) paillierPublicProofDomainFor(party tss.PartyID, paillierPublicKey []byte) ([]byte, error) {
	config := tss.ThresholdConfig{
		Threshold: k.state.threshold,
		Parties:   k.state.parties,
		Self:      party,
		SessionID: k.state.paillierProofSessionID,
	}
	switch k.state.paillierProofDomain {
	case domainLabelKeygenModulus:
		return keygenModulusDomain(config, party, paillierPublicKey, k.state.planHash), nil
	case domainLabelRefreshPaillier:
		return refreshPaillierDomain(config, party, paillierPublicKey, k.state.planHash), nil
	case domainLabelResharePaillier:
		return resharePaillierDomain(config, party, paillierPublicKey, k.state.planHash), nil
	default:
		return nil, fmt.Errorf("unsupported paillier public proof domain %q", k.state.paillierProofDomain)
	}
}

func checkPaillierModulusBounds(pk *pai.PublicKey, limits Limits) error {
	if pk == nil || pk.N == nil {
		return errors.New("nil paillier public key")
	}
	if limits.Paillier.MaxModulusBits > 0 && pk.N.BitLen() > limits.Paillier.MaxModulusBits {
		return fmt.Errorf("paillier modulus has %d bits, max %d", pk.N.BitLen(), limits.Paillier.MaxModulusBits)
	}
	return zkpai.ActiveSecurityParams().CheckPaillierModulus(pk)
}

// Destroy zeros the local secret scalar, Paillier private-key bytes, and chain
// code in place. After Destroy, the KeyShare is permanently unusable for MPC
// operations.
//
// # Go zeroization boundaries
//
// Destroy zeroes the fields that this package controls: secret (fixed-length
// [secret.Scalar]), paillierPrivateKey (Paillier λ/μ), and ChainCode. It does
// not zero GroupCommitments, VerificationShares, or other public material —
// those fields contain no secret data. The Paillier private key that has been
// serialized to paillierPrivateKey may still have intermediate *big.Int values
// reachable via the GC; the paillier package's own Destroy function handles
// its in-memory representations. A shallow Go copy is only another handle to
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
	clear(k.state.paillierPrivateKey)
}

func (k *KeyShare) secretBig() (*big.Int, error) {
	return secpSecretBig(k.state.secret)
}

func (k *KeyShare) requireMPCMaterial() error {
	if err := k.Validate(); err != nil {
		return err
	}
	for _, id := range k.state.parties {
		if _, err := k.paillierPublicFor(id); err != nil {
			return err
		}
	}
	return nil
}

func (k *KeyShare) paillierPublic() (*pai.PublicKey, error) {
	limits := DefaultLimits()
	return pai.UnmarshalPublicKeyWithMaxModulusBits(k.state.paillierPublicKey, limits.Paillier.MaxModulusBits)
}

func (k *KeyShare) paillierPrivate() (*pai.PrivateKey, error) {
	return pai.UnmarshalPrivateKey(k.state.paillierPrivateKey)
}

func (k *KeyShare) paillierPublicFor(id tss.PartyID) (*pai.PublicKey, error) {
	if id == k.state.party {
		return k.paillierPublic()
	}
	for _, item := range k.state.paillierPublicKeys {
		if item.Party == id {
			limits := DefaultLimits()
			return pai.UnmarshalPublicKeyWithMaxModulusBits(item.PublicKey, limits.Paillier.MaxModulusBits)
		}
	}
	return nil, fmt.Errorf("missing Paillier public key for party %d", id)
}

// ringPedersenPublicFor returns the Ring-Pedersen parameters for a given party.
func (k *KeyShare) ringPedersenPublicFor(id tss.PartyID) (zkpai.RingPedersenParams, error) {
	limits := DefaultLimits()
	if id == k.state.party {
		params, err := zkpai.UnmarshalRingPedersenParamsWithMaxModulusBits(k.state.ringPedersenParams, limits.Paillier.MaxModulusBits)
		if err != nil {
			return zkpai.RingPedersenParams{}, err
		}
		return *params, nil
	}
	for _, item := range k.state.ringPedersenPublic {
		if item.Party == id {
			params, err := zkpai.UnmarshalRingPedersenParamsWithMaxModulusBits(item.Params, limits.Paillier.MaxModulusBits)
			if err != nil {
				return zkpai.RingPedersenParams{}, err
			}
			return *params, nil
		}
	}
	return zkpai.RingPedersenParams{}, fmt.Errorf("missing Ring-Pedersen params for party %d", id)
}

func (k *KeyShare) verificationShare(id tss.PartyID) ([]byte, bool) {
	for _, share := range k.state.verificationShares {
		if share.Party == id {
			return share.PublicKey, true
		}
	}
	return nil, false
}

func cloneKeyShareValue(k *KeyShare) *KeyShare {
	if k == nil || k.state == nil {
		return nil
	}
	return &KeyShare{state: &keyShareState{
		version:                k.state.version,
		party:                  k.state.party,
		threshold:              k.state.threshold,
		parties:                slices.Clone(k.state.parties),
		publicKey:              slices.Clone(k.state.publicKey),
		chainCode:              slices.Clone(k.state.chainCode),
		secret:                 k.state.secret.Clone(),
		groupCommitments:       wireutil.CloneByteSlices(k.state.groupCommitments),
		verificationShares:     cloneVerificationShares(k.state.verificationShares),
		paillierPublicKey:      slices.Clone(k.state.paillierPublicKey),
		paillierPrivateKey:     slices.Clone(k.state.paillierPrivateKey),
		paillierProof:          slices.Clone(k.state.paillierProof),
		paillierPublicKeys:     clonePaillierPublicShares(k.state.paillierPublicKeys),
		ringPedersenParams:     slices.Clone(k.state.ringPedersenParams),
		ringPedersenProof:      slices.Clone(k.state.ringPedersenProof),
		ringPedersenPublic:     cloneRingPedersenPublicShares(k.state.ringPedersenPublic),
		paillierProofSessionID: k.state.paillierProofSessionID,
		paillierProofDomain:    k.state.paillierProofDomain,
		resharePlanHash:        slices.Clone(k.state.resharePlanHash),
		planHash:               slices.Clone(k.state.planHash),
		shareProof:             slices.Clone(k.state.shareProof),
		keygenTranscriptHash:   slices.Clone(k.state.keygenTranscriptHash),
		logCiphertext:          slices.Clone(k.state.logCiphertext),
		logProof:               slices.Clone(k.state.logProof),
		keygenConfirmations:    wireutil.CloneByteSlices(k.state.keygenConfirmations),
	}}
}

func cloneVerificationShares(in []VerificationShare) []VerificationShare {
	if in == nil {
		return nil
	}
	out := make([]VerificationShare, len(in))
	for i := range out {
		out[i] = VerificationShare{
			Party:     in[i].Party,
			PublicKey: slices.Clone(in[i].PublicKey),
		}
	}
	return out
}
