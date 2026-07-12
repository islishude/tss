package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/transcript"
	"github.com/islishude/tss/internal/zk/signprep"
)

type presignVerificationContext struct {
	SessionID  tss.SessionID              `wire:"1,bytes,len=32"`
	Round1Echo []byte                     `wire:"2,bytes,len=32"`
	Entries    []presignVerificationEntry `wire:"3,recordlist,max_items=signers"`
}

type presignVerificationEntry struct {
	Party             tss.PartyID    `wire:"1,u32"`
	Gamma             []byte         `wire:"2,bytes,max_bytes=point"`
	EncK              []byte         `wire:"3,bytes,max_bytes=paillier_ciphertext"`
	PaillierPublicKey *pai.PublicKey `wire:"4,nested,max_bytes=paillier_public_key"`
	XBarPoint         *secp.Point    `wire:"5,custom,len=33"`
	Delta             *secp.Scalar   `wire:"6,custom,len=32"`
	KPoint            []byte         `wire:"7,bytes,len=33"`
	EncGamma          []byte         `wire:"8,bytes,max_bytes=paillier_ciphertext"`
}

func (v presignVerificationContext) clone() presignVerificationContext {
	entries := make([]presignVerificationEntry, len(v.Entries))
	for i := range v.Entries {
		entries[i] = v.Entries[i].clone()
	}
	return presignVerificationContext{
		SessionID:  v.SessionID,
		Round1Echo: bytes.Clone(v.Round1Echo),
		Entries:    entries,
	}
}

func (e presignVerificationEntry) clone() presignVerificationEntry {
	var delta *secp.Scalar
	if e.Delta != nil {
		cloned := *e.Delta
		delta = &cloned
	}
	return presignVerificationEntry{
		Party:             e.Party,
		Gamma:             bytes.Clone(e.Gamma),
		EncK:              bytes.Clone(e.EncK),
		PaillierPublicKey: e.PaillierPublicKey.Clone(),
		XBarPoint:         secp.Clone(e.XBarPoint),
		Delta:             delta,
		KPoint:            bytes.Clone(e.KPoint),
		EncGamma:          bytes.Clone(e.EncGamma),
	}
}

func (v *presignVerificationContext) destroy() {
	if v == nil {
		return
	}
	clear(v.Round1Echo)
	for i := range v.Entries {
		clear(v.Entries[i].Gamma)
		clear(v.Entries[i].EncK)
		clear(v.Entries[i].KPoint)
		clear(v.Entries[i].EncGamma)
		if v.Entries[i].PaillierPublicKey != nil {
			secret.ClearBigInt(v.Entries[i].PaillierPublicKey.N)
			secret.ClearBigInt(v.Entries[i].PaillierPublicKey.G)
			secret.ClearBigInt(v.Entries[i].PaillierPublicKey.NSquared)
		}
		v.Entries[i] = presignVerificationEntry{}
	}
	v.Entries = nil
	*v = presignVerificationContext{}
}

func validatePresignVerificationContext(signers tss.PartySet, context presignVerificationContext, limits Limits) error {
	if !context.SessionID.Valid() {
		return errors.New("invalid presign verification session ID")
	}
	if len(context.Round1Echo) != sha256.Size {
		return errors.New("invalid presign verification round1 echo")
	}
	if len(context.Entries) != len(signers) {
		return fmt.Errorf("presign verification entry count %d != signers %d", len(context.Entries), len(signers))
	}
	totalBytes := 4
	seen := make(map[tss.PartyID]struct{}, len(context.Entries))
	for i := range context.Entries {
		entry := &context.Entries[i]
		if entry.Party != signers[i] {
			return fmt.Errorf("presign verification party %d out of canonical signer order at index %d", entry.Party, i)
		}
		if _, ok := seen[entry.Party]; ok {
			return fmt.Errorf("duplicate presign verification party %d", entry.Party)
		}
		seen[entry.Party] = struct{}{}
		if _, err := secp.PointFromBytes(entry.Gamma); err != nil {
			return fmt.Errorf("invalid presign verification gamma for party %d: %w", entry.Party, err)
		}
		if err := validatePositiveIntegerBytes(entry.EncK); err != nil {
			return fmt.Errorf("invalid presign verification EncK for party %d: %w", entry.Party, err)
		}
		if err := validatePositiveIntegerBytes(entry.EncGamma); err != nil {
			return fmt.Errorf("invalid presign verification EncGamma for party %d: %w", entry.Party, err)
		}
		if _, err := secp.PointFromBytes(entry.KPoint); err != nil {
			return fmt.Errorf("invalid presign verification KPoint for party %d: %w", entry.Party, err)
		}
		if len(entry.EncK) > limits.Paillier.MaxCiphertextBytes {
			return fmt.Errorf("presign verification EncK too large: %d > %d", len(entry.EncK), limits.Paillier.MaxCiphertextBytes)
		}
		if len(entry.EncGamma) > limits.Paillier.MaxCiphertextBytes {
			return fmt.Errorf("presign verification EncGamma too large: %d > %d", len(entry.EncGamma), limits.Paillier.MaxCiphertextBytes)
		}
		if err := validatePaillierPublicKeyWithLimits(entry.PaillierPublicKey, limits); err != nil {
			return fmt.Errorf("invalid presign verification Paillier key for party %d: %w", entry.Party, err)
		}
		if _, err := secp.PointBytes(entry.XBarPoint); err != nil {
			return fmt.Errorf("invalid presign verification XBarPoint for party %d: %w", entry.Party, err)
		}
		if entry.Delta == nil {
			return fmt.Errorf("nil presign verification delta for party %d", entry.Party)
		}
		if entry.Delta.IsZero() {
			return fmt.Errorf("invalid zero presign verification delta for party %d", entry.Party)
		}
		publicKeyBytes, err := canonicalWireMessageBytes(entry.PaillierPublicKey, limits)
		if err != nil {
			return fmt.Errorf("encode presign verification Paillier key for party %d: %w", entry.Party, err)
		}
		entryBytes := len(entry.Gamma) + len(entry.EncK) + len(entry.EncGamma) + len(entry.KPoint) + len(publicKeyBytes) + 33 + 32 + 64
		if entryBytes > limits.SignPrep.MaxVerificationEntryBytes {
			return fmt.Errorf("presign verification entry too large: %d > %d", entryBytes, limits.SignPrep.MaxVerificationEntryBytes)
		}
		totalBytes += 4 + entryBytes
	}
	if totalBytes > limits.SignPrep.MaxVerificationContextBytes {
		return fmt.Errorf("presign verification context too large: %d > %d", totalBytes, limits.SignPrep.MaxVerificationContextBytes)
	}
	return nil
}

func presignRound1EchoFromState(state *presignState, limits Limits) ([]byte, error) {
	if state == nil {
		return nil, errors.New("nil presign state")
	}
	t := transcript.New(presignRound1EchoLabel)
	t.AppendBytes("session_id", state.Verification.SessionID[:])
	t.AppendBytes("plan_hash", state.PlanHash)
	t.AppendBytes("context_hash", state.ContextHash)
	t.AppendBytes("additive_shift", state.Derivation.AdditiveShift)
	for i := range state.Verification.Entries {
		entry := &state.Verification.Entries[i]
		paillierPublicKeyBytes, err := canonicalWireMessageBytes(entry.PaillierPublicKey, limits)
		if err != nil {
			return nil, fmt.Errorf("encode Paillier key for party %d: %w", entry.Party, err)
		}
		t.AppendUint32("signer", entry.Party)
		t.AppendBytes("gamma", entry.Gamma)
		t.AppendBytes("enc_k", entry.EncK)
		t.AppendBytes("enc_gamma", entry.EncGamma)
		t.AppendBytes("k_point", entry.KPoint)
		t.AppendBytes("paillier_public_key", paillierPublicKeyBytes)
	}
	return t.Sum(), nil
}

func presignTranscriptHashFromState(state *presignState, _ Limits) ([]byte, error) {
	if state == nil {
		return nil, errors.New("nil presign state")
	}
	rBytes, err := secp.PointBytes(state.R)
	if err != nil {
		return nil, err
	}
	deltaAggregate, err := secpScalarFromSecret(state.DeltaAggregate)
	if err != nil {
		return nil, err
	}
	t := transcript.New(presignTranscriptHashLabel)
	t.AppendBytes("session_id", state.Verification.SessionID[:])
	t.AppendBytes("plan_hash", state.PlanHash)
	t.AppendBytes("context_hash", state.ContextHash)
	t.AppendBytes("additive_shift", state.Derivation.AdditiveShift)
	publicKey, err := secp.PointBytes(state.PublicKey)
	if err != nil {
		return nil, err
	}
	t.AppendBytes("public_key", publicKey)
	t.AppendBytes("keygen_transcript_hash", state.KeygenTranscriptHash)
	t.AppendBytes("parties_hash", state.PartiesHash)
	for i, id := range state.Signers {
		entry := state.Verification.Entries[i]
		if entry.Party != id {
			return nil, errors.New("presign verification entries are not in signer order")
		}
		verifyShare, ok := presignVerifyShare(&Presign{state: state}, id)
		if !ok {
			return nil, fmt.Errorf("missing verify share for party %d", id)
		}
		kPointBytes, chiPointBytes, proofBytes, err := signVerifyShareBytes(verifyShare)
		if err != nil {
			return nil, err
		}
		proofHash := sha256.Sum256(proofBytes)
		t.AppendUint32("signer", id)
		t.AppendBytes("gamma", entry.Gamma)
		t.AppendBytes("enc_k", entry.EncK)
		t.AppendBytes("enc_gamma", entry.EncGamma)
		if entry.Delta == nil {
			return nil, fmt.Errorf("nil presign verification delta for party %d", id)
		}
		t.AppendBytes("delta_share", entry.Delta.Bytes())
		t.AppendBytes("k_point", kPointBytes)
		t.AppendBytes("chi_point", chiPointBytes)
		t.AppendBytes("proof_hash", proofHash[:])
	}
	t.AppendBytes("r_point", rBytes)
	t.AppendBytes("little_r", state.LittleR.Bytes())
	t.AppendBytes("delta", deltaAggregate.Bytes())
	return t.Sum(), nil
}

// VerifyCryptographicMaterial performs complete self-verification of persisted
// presign protocol material.
func (p *Presign) VerifyCryptographicMaterial() error {
	return p.VerifyCryptographicMaterialWithLimits(DefaultLimits())
}

// VerifyCryptographicMaterialWithLimits replays the persisted public proof
// checks and verifies local secret/public consistency using explicit limits.
func (p *Presign) VerifyCryptographicMaterialWithLimits(limits Limits) error {
	if err := p.ValidateWithLimits(limits); err != nil {
		return err
	}
	computedEcho, err := presignRound1EchoFromState(p.state, limits)
	if err != nil {
		return err
	}
	if !bytes.Equal(computedEcho, p.state.Verification.Round1Echo) {
		return errors.New("presign round1 echo mismatch")
	}
	publicKey, err := secp.PointBytes(p.state.PublicKey)
	if err != nil {
		return err
	}
	for i, id := range p.state.Signers {
		entry := p.state.Verification.Entries[i]
		verifyShare := p.state.VerifyShares[i]
		if entry.Party != id || verifyShare.Party != id {
			return errors.New("presign verification material is not in signer order")
		}
		kPointBytes, chiPointBytes, _, err := signVerifyShareBytes(verifyShare)
		if err != nil {
			return fmt.Errorf("presign verify share party %d: %w", id, err)
		}
		if !bytes.Equal(kPointBytes, entry.KPoint) {
			return fmt.Errorf("presign KPoint for party %d does not match round1 relation", id)
		}
		xBarPoint, err := secp.PointBytes(entry.XBarPoint)
		if err != nil {
			return err
		}
		paillierPublicKey, err := canonicalWireMessageBytes(entry.PaillierPublicKey, limits)
		if err != nil {
			return err
		}
		stmt := signprep.Statement{
			Protocol:              tss.ProtocolCGGMP21Secp256k1,
			SessionID:             p.state.Verification.SessionID,
			Party:                 id,
			Signers:               slices.Clone(p.state.Signers),
			PlanHash:              slices.Clone(p.state.PlanHash),
			ContextHash:           slices.Clone(p.state.ContextHash),
			AdditiveShift:         slices.Clone(p.state.Derivation.AdditiveShift),
			PublicKey:             publicKey,
			KeygenTranscriptHash:  slices.Clone(p.state.KeygenTranscriptHash),
			PartiesHash:           slices.Clone(p.state.PartiesHash),
			KPoint:                kPointBytes,
			ChiPoint:              chiPointBytes,
			XBarPoint:             xBarPoint,
			Gamma:                 slices.Clone(entry.Gamma),
			EncK:                  slices.Clone(entry.EncK),
			PaillierPublicKey:     paillierPublicKey,
			Round1Echo:            computedEcho,
			Round2CommitmentsHash: bytes.Clone(verifyShare.Round2CommitmentsHash),
			MTAContributionsHash:  bytes.Clone(verifyShare.MTAContributionsHash),
			MTABasePoint:          bytes.Clone(verifyShare.MTABasePoint),
			MTAOffsetPoint:        bytes.Clone(verifyShare.MTAOffsetPoint),
			DeltaBasePoint:        bytes.Clone(verifyShare.DeltaBasePoint),
			DeltaOffsetPoint:      bytes.Clone(verifyShare.DeltaOffsetPoint),
			Delta:                 entry.Delta.Bytes(),
		}
		if err := signprep.Verify(stmt, verifyShare.Proof); err != nil {
			return fmt.Errorf("presign signprep proof for party %d: %w", id, err)
		}
	}
	computedTranscript, err := presignTranscriptHashFromState(p.state, limits)
	if err != nil {
		return err
	}
	if !bytes.Equal(computedTranscript, p.state.TranscriptHash) {
		return errors.New("presign transcript hash mismatch")
	}
	localVerifyShare, ok := presignVerifyShare(p, p.state.Party)
	if !ok {
		return errors.New("missing local presign verify share")
	}
	kShare, err := secpScalarFromSecret(p.state.KShare)
	if err != nil {
		return err
	}
	if !secp.Equal(secp.ScalarBaseMult(kShare), localVerifyShare.KPoint) {
		return errors.New("presign local k share does not match KPoint")
	}
	chiShare, err := secpScalarFromSecret(p.state.ChiShare)
	if err != nil {
		return err
	}
	if !secp.Equal(secp.ScalarBaseMult(chiShare), localVerifyShare.ChiPoint) {
		return errors.New("presign local chi share does not match ChiPoint")
	}
	deltaSum := secp.ScalarZero()
	gammaPoints := make([]*secp.Point, 0, len(p.state.Verification.Entries))
	for i := range p.state.Verification.Entries {
		entry := &p.state.Verification.Entries[i]
		if entry.Delta == nil {
			return fmt.Errorf("nil presign verification delta for party %d", entry.Party)
		}
		deltaSum = secp.ScalarAdd(deltaSum, *entry.Delta)
		gammaPoint, err := secp.PointFromBytes(entry.Gamma)
		if err != nil {
			return err
		}
		gammaPoints = append(gammaPoints, gammaPoint)
	}
	deltaAggregate, err := secpScalarFromSecret(p.state.DeltaAggregate)
	if err != nil {
		return err
	}
	if !deltaSum.Equal(deltaAggregate) {
		return errors.New("presign aggregate delta mismatch")
	}
	deltaInverse, err := secp.ScalarInvert(deltaSum)
	if err != nil {
		return errors.New("presign aggregate delta is not invertible")
	}
	recomputedR := secp.ScalarMult(secp.AddPoints(gammaPoints...), deltaInverse)
	if !secp.Equal(recomputedR, p.state.R) {
		return errors.New("presign R does not match verification material")
	}
	if !secp.ScalarFromFieldElement(recomputedR.X).Equal(p.state.LittleR) {
		return errors.New("presign little r does not match R")
	}
	return nil
}
