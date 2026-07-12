package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/sessiontx"
	"github.com/islishude/tss/internal/transcript"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
	"github.com/islishude/tss/internal/zk/schnorr"
)

func (s *KeygenSession) tryAdvance() ([]tss.Envelope, error) {
	if s.completed {
		return nil, nil
	}
	if s.pending == nil {
		shareOut, err := s.emitEncryptedKeygenShares()
		if err != nil {
			return nil, err
		}
		snap, ok, err := s.round1.snapshot()
		if err != nil || !ok {
			return shareOut, err
		}
		defer snap.Destroy()
		completionOut, err := s.completeRound1(snap)
		return append(shareOut, completionOut...), err
	}
	snap, ok, err := s.confirmations.snapshot()
	if err != nil || !ok {
		return nil, err
	}
	defer snap.Destroy()
	return nil, s.completeConfirmationRound(snap)
}

func (s *KeygenSession) completeRound1(snap *keygenRound1Snapshot) ([]tss.Envelope, error) {
	prepared, err := s.preparePendingKeyShare(snap)
	if err != nil {
		return nil, err
	}
	defer prepared.destroy()
	effects, err := s.commitCGGMPPendingKeyShare(prepared)
	if err != nil {
		return nil, err
	}
	confirmationSnap, ok, err := s.confirmations.snapshot()
	if err != nil {
		return nil, err
	}
	if ok {
		defer confirmationSnap.Destroy()
		if err := s.completeConfirmationRound(confirmationSnap); err != nil {
			return nil, err
		}
	}
	return effects.envelopes, nil
}

type preparedCGGMPPendingKeyShare struct {
	share        *KeyShare
	confirmation *KeygenConfirmation
	env          tss.Envelope
	committed    bool
}

func (p *preparedCGGMPPendingKeyShare) destroy() {
	if p == nil || p.committed {
		return
	}
	if p.share != nil {
		p.share.Destroy()
		p.share = nil
	}
	if p.confirmation != nil {
		clear(p.confirmation.ChainCode)
		p.confirmation = nil
	}
	clear(p.env.Payload)
}

func (s *KeygenSession) maybePrepareCGGMPPendingKeyShare() (*preparedCGGMPPendingKeyShare, bool, error) {
	snap, ok, err := s.round1.snapshot()
	if err != nil || !ok {
		return nil, ok, err
	}
	defer snap.Destroy()
	prepared, err := s.preparePendingKeyShare(snap)
	if err != nil {
		return nil, false, err
	}
	return prepared, true, nil
}

func (s *KeygenSession) preparePendingKeyShare(snap *keygenRound1Snapshot) (*preparedCGGMPPendingKeyShare, error) {
	if snap == nil {
		return nil, errors.New("nil keygen round1 snapshot")
	}
	if s.local == nil || s.local.paillier == nil {
		return nil, errors.New("missing keygen local material")
	}
	if err := verifyRound1Shares(s.cfg, snap); err != nil {
		dealer := verificationDealer(err)
		return nil, tss.NewProtocolError(tss.ErrCodeInvariant, keygenShareRound, dealer,
			fmt.Errorf("verified encrypted keygen share failed completion recheck: %w", err))
	}
	secretScalar, err := aggregateKeygenSecret(snap.parties, snap.shares)
	if err != nil {
		return nil, err
	}
	cleanup := sessiontx.NewCleanupStack()
	defer cleanup.Run()
	shareOwnsSecret := false
	cleanup.Add(func() {
		if !shareOwnsSecret {
			secretScalar.Destroy()
		}
	})
	groupCommitments, err := aggregateKeygenCommitments(snap.parties, s.cfg.Threshold, snap.commitments)
	if err != nil {
		return nil, err
	}
	publicKey, err := secp.PointBytes(groupCommitments[0])
	if err != nil {
		return nil, err
	}
	verificationShares, err := deriveVerificationShareSet(snap.parties, groupCommitments)
	if err != nil {
		return nil, err
	}
	transcriptHash, err := s.keygenTranscriptHash(snap, groupCommitments)
	if err != nil {
		return nil, err
	}
	localVerificationShare, ok := verificationShares[s.cfg.Self]
	if !ok {
		return nil, errors.New("missing local verification share")
	}
	shareProof, proofPublic, err := schnorr.Prove(transcriptHash, secretScalar)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(proofPublic, localVerificationShare) {
		return nil, errors.New("local share proof public key mismatch")
	}
	localProofShare := &KeyShare{state: &keyShareState{
		SecurityParams: s.securityParams,
		Party:          s.cfg.Self,
		Threshold:      s.cfg.Threshold,
		Parties:        s.cfg.Parties,
		PublicKey:      publicKey,
		PartyData: map[tss.PartyID]keySharePartyData{
			s.cfg.Self: {PaillierPublicKey: s.local.paillier.PublicKey.Clone()},
		},
		PlanHash:               bytes.Clone(s.planHash),
		KeygenTranscriptHash:   transcriptHash,
		PaillierProofSessionID: s.cfg.SessionID,
		PaillierProofDomain:    domainLabelKeygenModulus,
	}}
	localPaillierDomain, err := keySharePaillierProofDomain(localProofShare, s.limits)
	if err != nil {
		return nil, err
	}
	localPaillierProof, err := zkpai.ProveModulus(s.cfg.Reader(), localPaillierDomain, s.local.paillier, s.cfg.Self)
	if err != nil {
		return nil, err
	}
	localRingPedersen := snap.ringPedersen[s.cfg.Self]
	partyData := make(map[tss.PartyID]keySharePartyData, len(s.cfg.Parties))
	for _, id := range s.cfg.Parties {
		verificationShare, ok := verificationShares[id]
		if !ok {
			return nil, fmt.Errorf("missing verification share for party %d", id)
		}
		paillierProof := snap.paillier[id].Proof
		if id == s.cfg.Self {
			paillierProof = localPaillierProof
		}
		partyData[id] = keySharePartyData{
			VerificationShare:   bytes.Clone(verificationShare),
			PaillierPublicKey:   snap.paillier[id].PublicKey.Clone(),
			PaillierProof:       paillierProof.Clone(),
			RingPedersenParams:  snap.ringPedersen[id].Params.Clone(),
			RingPedersenProof:   snap.ringPedersen[id].Proof.Clone(),
			PaillierFactorProof: snap.factorProofs[id].Clone(),
		}
	}
	share := &KeyShare{state: &keyShareState{
		SecurityParams:         s.securityParams,
		Party:                  s.cfg.Self,
		Threshold:              s.cfg.Threshold,
		Parties:                s.cfg.Parties.Clone(),
		PublicKey:              bytes.Clone(publicKey),
		ChainCode:              nil,
		Secret:                 secretScalar,
		GroupCommitments:       groupCommitments,
		PartyData:              partyData,
		PaillierPrivateKey:     s.local.paillier.Clone(),
		PaillierProofSessionID: s.cfg.SessionID,
		PaillierProofDomain:    domainLabelKeygenModulus,
		ShareProof:             shareProof.Clone(),
		PlanHash:               bytes.Clone(s.planHash),
		KeygenTranscriptHash:   transcriptHash,
	}}
	shareOwnsSecret = true
	cleanup.Add(share.Destroy)
	logCiphertext, logRandomness, err := s.local.paillier.EncryptSecret(s.cfg.Reader(), secretScalar)
	if err != nil {
		return nil, err
	}
	defer logRandomness.Destroy()
	localRP := localRingPedersen.Params.Clone()
	logDomain, err := logProofDomain(localProofShare, s.local.paillier.PublicKey, localVerificationShare, transcriptHash, s.limits)
	if err != nil {
		return nil, err
	}
	verificationPoint, err := secp.PointFromBytes(localVerificationShare)
	if err != nil {
		return nil, fmt.Errorf("invalid verification share: %w", err)
	}
	logStmt := zkpai.LogStarStatement{
		PaillierN:   s.local.paillier.PublicKey,
		C:           logCiphertext,
		X:           verificationPoint,
		B:           secp.ScalarBaseMult(secp.ScalarOne()),
		VerifierAux: localRP,
	}
	logWitness := zkpai.LogStarWitness{X: secretScalar, Rho: logRandomness}
	logProof, err := zkpai.ProveLogStar(s.securityParams, logDomain, logStmt, logWitness, s.cfg.Reader())
	if err != nil {
		return nil, err
	}
	share.state.LogCiphertext = tss.CloneBigInt(logCiphertext)
	share.state.LogProof = logProof.Clone()
	confirmation, err := newKeygenCommitRevealConfirmation(share, s.local.chainCode, s.limits)
	if err != nil {
		return nil, err
	}
	encodedConfirmation, err := confirmation.MarshalBinary()
	if err != nil {
		clear(confirmation.ChainCode)
		return nil, err
	}
	confirmationEnv, err := newEnvelope(s.cfg, keygenConfirmationRound, s.cfg.Self, tss.BroadcastPartyId, payloadKeygenConfirmation, encodedConfirmation)
	if err != nil {
		clear(encodedConfirmation)
		clear(confirmation.ChainCode)
		return nil, err
	}
	cleanup.Disarm()
	return &preparedCGGMPPendingKeyShare{
		share:        share,
		confirmation: confirmation,
		env:          confirmationEnv,
	}, nil
}

func verifyRound1Shares(cfg tss.ThresholdConfig, snap *keygenRound1Snapshot) error {
	for _, id := range snap.parties {
		share, err := secpScalarFromSecretAllowZero(snap.shares[id])
		if err != nil {
			return err
		}
		if err := secp.VerifyShare(snap.commitments[id], cfg.Self, share); err != nil {
			return keygenShareVerificationError{dealer: id, err: err}
		}
	}
	return nil
}

type keygenShareVerificationError struct {
	dealer tss.PartyID
	err    error
}

// Error returns the underlying share-verification failure.
func (e keygenShareVerificationError) Error() string { return e.err.Error() }

// Unwrap exposes the underlying share-verification failure.
func (e keygenShareVerificationError) Unwrap() error { return e.err }

func verificationDealer(err error) tss.PartyID {
	if verificationErr, ok := errors.AsType[keygenShareVerificationError](err); ok {
		return verificationErr.dealer
	}
	return tss.BroadcastPartyId
}

func aggregateKeygenSecret(parties tss.PartySet, shares map[tss.PartyID]*secret.Scalar) (*secret.Scalar, error) {
	localSecret := secp.ScalarZero()
	for _, id := range parties {
		share, ok := shares[id]
		if !ok || share == nil {
			return nil, fmt.Errorf("missing keygen share from party %d", id)
		}
		scalar, err := secpScalarFromSecretAllowZero(share)
		if err != nil {
			return nil, err
		}
		localSecret = secp.ScalarAdd(localSecret, scalar)
	}
	return secpSecretScalarFromScalar(localSecret)
}

func deriveVerificationShareSet(
	parties tss.PartySet,
	commitments []*secp.Point,
) (map[tss.PartyID][]byte, error) {
	out := make(map[tss.PartyID][]byte, len(parties))
	for _, id := range parties {
		pub, err := secp.EvalCommitmentPoints(commitments, id)
		if err != nil {
			return nil, err
		}
		encoded, err := secp.PointBytes(pub)
		if err != nil {
			return nil, err
		}
		if _, exists := out[id]; exists {
			return nil, fmt.Errorf("duplicate verification share for party %d", id)
		}
		out[id] = encoded
	}
	return out, nil
}

func (s *KeygenSession) commitCGGMPPendingKeyShare(p *preparedCGGMPPendingKeyShare) (sessionEffects, error) {
	if p == nil {
		return sessionEffects{}, errors.New("nil prepared keygen share")
	}
	if err := s.confirmations.record(s.cfg.Self, p.confirmation); err != nil {
		return sessionEffects{}, err
	}
	s.pending = p.share
	s.state = keygenAwaitingConfirmations
	if s.local != nil {
		s.local.Destroy()
		s.local = nil
	}
	p.committed = true
	publicKey := p.share.state.PublicKey
	pubKeyHash := sha256.Sum256(publicKey)
	s.cfg.Logger().Info(s.cfg.Ctx(), "keygen local material complete",
		"party_id", s.cfg.Self,
		"session_id", fmt.Sprintf("%x", s.cfg.SessionID[:8]),
		"public_key_hash", fmt.Sprintf("%x", pubKeyHash[:8]),
	)
	return sessionEffects{envelopes: []tss.Envelope{p.env}}, nil
}

// abort marks the session aborted and clears all secret-bearing accumulated
// state so that secret material from an incomplete keygen is not retained in
// process memory longer than necessary. Callers that also want to release
// non-secret storage (commits, confirmations) should call Destroy.
func (s *KeygenSession) abort() {
	if s == nil {
		return
	}
	s.aborted = true
	s.state = keygenAborted
	if s.local != nil {
		s.local.Destroy()
		s.local = nil
	}
	if s.round1 != nil {
		s.round1.Destroy()
	}
	if s.confirmations != nil {
		s.confirmations.Destroy()
	}
	for id, confirmation := range s.pendingConfirmations {
		if confirmation != nil {
			clear(confirmation.ChainCode)
		}
		delete(s.pendingConfirmations, id)
	}
	if s.pending != nil {
		s.pending.Destroy()
		s.pending = nil
	}
}

func (s *KeygenSession) keygenTranscriptHash(snap *keygenRound1Snapshot, groupCommitments []*secp.Point) ([]byte, error) {
	groupCommitmentBytes, err := secp.CommitmentPointsBytes(groupCommitments)
	if err != nil {
		return nil, err
	}
	t := transcript.New(keygenTranscriptHashLabel)
	t.AppendBytes("session_id", s.cfg.SessionID[:])
	t.AppendBytes("plan_hash", s.planHash)
	for _, id := range tss.SortParties(s.cfg.Parties) {
		paillierSnapshot, err := snap.paillier[id].snapshot(s.limits)
		if err != nil {
			return nil, err
		}
		ringPedersenSnapshot, err := snap.ringPedersen[id].snapshot(s.limits)
		if err != nil {
			return nil, err
		}
		t.AppendUint32("party", id)
		t.AppendBytesList("commitments", snap.commitments[id])
		t.AppendBytes("paillier_public_key", paillierSnapshot.PublicKey)
		t.AppendBytes("paillier_proof", paillierSnapshot.Proof)
		t.AppendBytes("ring_pedersen_params", ringPedersenSnapshot.Params)
		t.AppendBytes("ring_pedersen_proof", ringPedersenSnapshot.Proof)
		t.AppendBytes("chain_code_commitment", snap.chainCodeCommits[id])
	}
	t.AppendBytesList("group_commitments", groupCommitmentBytes)
	return t.Sum(), nil
}

func verificationShareFor(shares []VerificationShare, id tss.PartyID) ([]byte, bool) {
	for _, share := range shares {
		if share.Party == id {
			return share.PublicKey, true
		}
	}
	return nil, false
}
