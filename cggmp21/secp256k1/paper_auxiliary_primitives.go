package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/shamir"
	"github.com/islishude/tss/internal/transcript"
	"github.com/islishude/tss/internal/wire"
)

const (
	figure6CommitmentLabel       = "cggmp21-secp256k1-figure6-keygen-commitment"
	figure6SchnorrDomainLabel    = "cggmp21-secp256k1-figure6-schnorr-domain"
	figure7CommitmentLabel       = "cggmp21-secp256k1-figure7-auxinfo-commitment"
	figure7RingPedersenLabel     = "cggmp21-secp256k1-figure7-ring-pedersen-domain"
	figure7SchnorrDomainLabel    = "cggmp21-secp256k1-figure7-schnorr-domain"
	figure7ModulusDomainLabel    = "cggmp21-secp256k1-figure7-modulus-domain"
	figure7FactorDomainLabel     = "cggmp21-secp256k1-figure7-factor-domain"
	figure7DHMaskLabel           = "cggmp21-secp256k1-figure7-dh-mask"
	figure7TranscriptHashLabel   = "cggmp21-secp256k1-figure7-transcript"
	maxFigure7DHMaskCandidates   = 256
	figureCoinContributionLength = sha256.Size
)

var errFigure7ShareMismatch = errors.New("figure 7 share does not match polynomial commitments")

type auxInfoDHKey struct {
	Party     tss.PartyID `wire:"1,u32"`
	PublicKey []byte      `wire:"2,bytes,max_bytes=point"`
}

func (k auxInfoDHKey) clone() auxInfoDHKey {
	return auxInfoDHKey{Party: k.Party, PublicKey: bytes.Clone(k.PublicKey)}
}

func validateAuxInfoDHKeys(keys []auxInfoDHKey, parties tss.PartySet, sender tss.PartyID) error {
	if !parties.Contains(sender) {
		return fmt.Errorf("auxinfo DH sender %d is not a participant", sender)
	}
	if len(keys) != len(parties)-1 {
		return fmt.Errorf("auxinfo DH key count %d != %d", len(keys), len(parties)-1)
	}
	last := tss.PartyID(0)
	seen := make(map[tss.PartyID]struct{}, len(keys))
	for i, key := range keys {
		if key.Party == tss.BroadcastPartyId || key.Party == sender || !parties.Contains(key.Party) {
			return fmt.Errorf("invalid auxinfo DH recipient %d", key.Party)
		}
		if i > 0 && key.Party <= last {
			return errors.New("auxinfo DH recipients must be strictly increasing")
		}
		if _, ok := seen[key.Party]; ok {
			return fmt.Errorf("duplicate auxinfo DH recipient %d", key.Party)
		}
		if _, err := secp.PointFromBytes(key.PublicKey); err != nil {
			return fmt.Errorf("invalid auxinfo DH public key for party %d: %w", key.Party, err)
		}
		seen[key.Party] = struct{}{}
		last = key.Party
	}
	for _, party := range parties {
		if party == sender {
			continue
		}
		if _, ok := seen[party]; !ok {
			return fmt.Errorf("missing auxinfo DH public key for party %d", party)
		}
	}
	return nil
}

func auxInfoDHKeyFor(keys []auxInfoDHKey, party tss.PartyID) ([]byte, bool) {
	for _, key := range keys {
		if key.Party == party {
			return bytes.Clone(key.PublicKey), true
		}
	}
	return nil, false
}

func sampleFigureCoin(reader io.Reader) ([]byte, error) {
	if reader == nil {
		return nil, errors.New("nil figure coin reader")
	}
	out := make([]byte, figureCoinContributionLength)
	if _, err := io.ReadFull(reader, out); err != nil {
		clear(out)
		return nil, err
	}
	return out, nil
}

func xorFigureCoins(parties tss.PartySet, contributions map[tss.PartyID][]byte, name string) (tss.SessionID, error) {
	if err := wire.ValidateStrictSortedIDs(parties); err != nil {
		return tss.SessionID{}, fmt.Errorf("%s coin parties: %w", name, err)
	}
	var out tss.SessionID
	for _, party := range parties {
		contribution, ok := contributions[party]
		if !ok {
			return tss.SessionID{}, fmt.Errorf("missing %s contribution from party %d", name, party)
		}
		if len(contribution) != figureCoinContributionLength {
			return tss.SessionID{}, fmt.Errorf("%s contribution from party %d must be %d bytes", name, party, figureCoinContributionLength)
		}
		for i := range out {
			out[i] ^= contribution[i]
		}
	}
	if !out.Valid() {
		return tss.SessionID{}, fmt.Errorf("derived %s is zero", name)
	}
	return out, nil
}

func figure6Commitment(
	sid tss.SessionID,
	party tss.PartyID,
	rho, publicShare, schnorrCommitment, decommitment, planHash []byte,
) ([]byte, error) {
	if !sid.Valid() || party == tss.BroadcastPartyId {
		return nil, errors.New("invalid Figure 6 commitment identity")
	}
	if len(rho) != sha256.Size || len(decommitment) != sha256.Size || len(planHash) != sha256.Size {
		return nil, errors.New("invalid Figure 6 fixed-width commitment input")
	}
	if _, err := secp.PointFromBytes(publicShare); err != nil {
		return nil, fmt.Errorf("invalid Figure 6 public share: %w", err)
	}
	if _, err := secp.PointFromBytes(schnorrCommitment); err != nil {
		return nil, fmt.Errorf("invalid Figure 6 Schnorr commitment: %w", err)
	}
	t := transcript.New(figure6CommitmentLabel)
	t.AppendBytes("sid", sid[:])
	t.AppendUint32("party", party)
	t.AppendBytes("rho", rho)
	t.AppendBytes("public_share", publicShare)
	t.AppendBytes("schnorr_commitment", schnorrCommitment)
	t.AppendBytes("decommitment", decommitment)
	t.AppendBytes("plan_hash", planHash)
	return t.Sum(), nil
}

func figure6SchnorrDomain(sid, rho tss.SessionID, party tss.PartyID, planHash []byte) ([]byte, error) {
	if !sid.Valid() || !rho.Valid() || party == tss.BroadcastPartyId || len(planHash) != sha256.Size {
		return nil, errors.New("invalid Figure 6 Schnorr domain input")
	}
	t := transcript.New(figure6SchnorrDomainLabel)
	t.AppendBytes("sid", sid[:])
	t.AppendUint32("party", party)
	t.AppendBytes("rho", rho[:])
	t.AppendBytes("plan_hash", planHash)
	return t.Sum(), nil
}

func figure7ProofDomain(
	label string,
	stableSID, runSessionID, rid tss.SessionID,
	epochID []byte,
	parties tss.PartySet,
	threshold int,
	prover, verifier tss.PartyID,
	coefficient int,
	planHash []byte,
) ([]byte, error) {
	if !stableSID.Valid() || !runSessionID.Valid() || !rid.Valid() || len(epochID) != sha256.Size || prover == tss.BroadcastPartyId || len(planHash) != sha256.Size {
		return nil, errors.New("invalid Figure 7 proof domain input")
	}
	if err := wire.ValidateStrictSortedIDs(parties); err != nil {
		return nil, err
	}
	if !parties.Contains(prover) || (verifier != tss.BroadcastPartyId && !parties.Contains(verifier)) {
		return nil, errors.New("figure 7 proof party is outside participant set")
	}
	if threshold <= 0 || threshold > len(parties) || coefficient < -1 || coefficient >= threshold {
		return nil, errors.New("invalid Figure 7 proof threshold or coefficient")
	}
	t := transcript.New(label)
	t.AppendBytes("stable_sid", stableSID[:])
	t.AppendBytes("run_session_id", runSessionID[:])
	t.AppendBytes("rid", rid[:])
	t.AppendBytes("epoch_id", epochID)
	t.AppendUint32List("parties", parties)
	t.AppendUint32("threshold", uint32(threshold))
	t.AppendUint32("prover", prover)
	t.AppendBool("has_verifier", verifier != tss.BroadcastPartyId)
	if verifier != tss.BroadcastPartyId {
		t.AppendUint32("verifier", verifier)
	}
	t.AppendBool("has_coefficient", coefficient >= 0)
	if coefficient >= 0 {
		t.AppendUint32("coefficient", uint32(coefficient))
	}
	t.AppendBytes("plan_hash", planHash)
	return t.Sum(), nil
}

func figure7RingPedersenDomain(
	stableSID, runSessionID tss.SessionID,
	parties tss.PartySet,
	threshold int,
	prover tss.PartyID,
	paramsBytes, planHash []byte,
) ([]byte, error) {
	if !stableSID.Valid() || !runSessionID.Valid() || prover == tss.BroadcastPartyId || len(paramsBytes) == 0 || len(planHash) != sha256.Size {
		return nil, errors.New("invalid Figure 7 Ring-Pedersen domain input")
	}
	if err := wire.ValidateStrictSortedIDs(parties); err != nil {
		return nil, err
	}
	if !parties.Contains(prover) || threshold <= 0 || threshold > len(parties) {
		return nil, errors.New("invalid Figure 7 Ring-Pedersen parties or threshold")
	}
	t := transcript.New(figure7RingPedersenLabel)
	t.AppendBytes("stable_sid", stableSID[:])
	t.AppendBytes("run_session_id", runSessionID[:])
	t.AppendUint32List("parties", parties)
	t.AppendUint32("threshold", uint32(threshold))
	t.AppendUint32("prover", prover)
	t.AppendBytes("params", paramsBytes)
	t.AppendBytes("plan_hash", planHash)
	return t.Sum(), nil
}

func figure7SchnorrDomain(stableSID, runSessionID, rid tss.SessionID, epochID []byte, parties tss.PartySet, threshold int, prover tss.PartyID, coefficient int, planHash []byte) ([]byte, error) {
	return figure7ProofDomain(figure7SchnorrDomainLabel, stableSID, runSessionID, rid, epochID, parties, threshold, prover, tss.BroadcastPartyId, coefficient, planHash)
}

func figure7ModulusDomain(stableSID, runSessionID, rid tss.SessionID, epochID []byte, parties tss.PartySet, threshold int, prover tss.PartyID, planHash []byte) ([]byte, error) {
	return figure7ProofDomain(figure7ModulusDomainLabel, stableSID, runSessionID, rid, epochID, parties, threshold, prover, tss.BroadcastPartyId, -1, planHash)
}

func figure7FactorDomain(stableSID, runSessionID, rid tss.SessionID, epochID []byte, parties tss.PartySet, threshold int, prover, verifier tss.PartyID, planHash []byte) ([]byte, error) {
	return figure7ProofDomain(figure7FactorDomainLabel, stableSID, runSessionID, rid, epochID, parties, threshold, prover, verifier, -1, planHash)
}

func figure7DHSharedSecret(peerPublic []byte, localSecret *secret.Scalar) ([]byte, error) {
	if localSecret == nil || localSecret.FixedLen() != secp.ScalarSize {
		return nil, errors.New("invalid Figure 7 DH secret")
	}
	peer, err := secp.PointFromBytes(peerPublic)
	if err != nil {
		return nil, fmt.Errorf("invalid Figure 7 DH peer public key: %w", err)
	}
	secretBytes := localSecret.FixedBytes()
	defer clear(secretBytes)
	scalar, err := secp.ScalarFromBytes(secretBytes)
	if err != nil {
		return nil, errors.New("invalid Figure 7 DH secret scalar")
	}
	defer scalar.Set(secp.ScalarZero())
	return secp.PointBytes(secp.ScalarMult(peer, scalar))
}

func deriveFigure7DHMask(
	stableSID, runSessionID, rid tss.SessionID,
	epochID []byte,
	sender, receiver tss.PartyID,
	sharedPoint, planHash []byte,
) (secp.Scalar, error) {
	if !stableSID.Valid() || !runSessionID.Valid() || !rid.Valid() || sender == tss.BroadcastPartyId || receiver == tss.BroadcastPartyId || sender == receiver {
		return secp.Scalar{}, errors.New("invalid Figure 7 DH mask identity")
	}
	if len(planHash) != sha256.Size {
		return secp.Scalar{}, errors.New("figure 7 DH mask plan hash must be 32 bytes")
	}
	if len(epochID) != sha256.Size {
		return secp.Scalar{}, errors.New("figure 7 DH mask epoch id must be 32 bytes")
	}
	if _, err := secp.PointFromBytes(sharedPoint); err != nil {
		return secp.Scalar{}, fmt.Errorf("invalid Figure 7 DH shared point: %w", err)
	}
	for counter := range uint32(maxFigure7DHMaskCandidates) {
		t := transcript.New(figure7DHMaskLabel)
		t.AppendBytes("stable_sid", stableSID[:])
		t.AppendBytes("run_session_id", runSessionID[:])
		t.AppendBytes("rid", rid[:])
		t.AppendBytes("epoch_id", epochID)
		t.AppendUint32("sender", sender)
		t.AppendUint32("receiver", receiver)
		t.AppendBytes("shared_point", sharedPoint)
		t.AppendBytes("plan_hash", planHash)
		t.AppendUint32("counter", counter)
		candidate, err := secp.ScalarFromBytesAllowZero(t.Sum())
		if err == nil {
			return candidate, nil
		}
	}
	return secp.Scalar{}, errors.New("figure 7 DH mask rejection sampling exhausted")
}

func maskFigure7Share(share, mask secp.Scalar) []byte {
	return secp.ScalarAdd(share, mask).Bytes()
}

func unmaskFigure7Share(masked []byte, mask secp.Scalar) (secp.Scalar, error) {
	ciphertext, err := secp.ScalarFromBytesAllowZero(masked)
	if err != nil {
		return secp.Scalar{}, fmt.Errorf("invalid Figure 7 masked share: %w", err)
	}
	return secp.ScalarSub(ciphertext, mask), nil
}

func evaluateFigure7Polynomial(poly shamir.Polynomial, epoch *EpochContext, receiver tss.PartyID) (secp.Scalar, error) {
	if epoch == nil {
		return secp.Scalar{}, errors.New("missing Figure 7 epoch context")
	}
	identifierBytes, ok := epoch.Identifier(receiver)
	if !ok {
		return secp.Scalar{}, fmt.Errorf("missing Figure 7 identifier for party %d", receiver)
	}
	defer clear(identifierBytes)
	identifier, err := shamir.IdentifierFromBytes(identifierBytes)
	if err != nil {
		return secp.Scalar{}, err
	}
	return shamir.EvalAt(poly, identifier)
}

func verifyFigure7Share(commitments [][]byte, identifier, share []byte) error {
	points, err := secp.CommitmentPointsFromBytes(commitments)
	if err != nil {
		return err
	}
	expected, err := evaluateCommitmentPointsAtIdentifier(points, identifier)
	if err != nil {
		return err
	}
	scalar, err := secp.ScalarFromBytesAllowZero(share)
	if err != nil {
		return fmt.Errorf("invalid Figure 7 share scalar: %w", err)
	}
	if !secp.Equal(secp.ScalarBaseMult(scalar), expected) {
		return errFigure7ShareMismatch
	}
	return nil
}
