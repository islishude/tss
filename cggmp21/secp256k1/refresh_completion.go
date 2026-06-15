package secp256k1

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/transcript"
	"github.com/islishude/tss/internal/wire/wireutil"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
	"github.com/islishude/tss/internal/zk/schnorr"
)

func (s *RefreshSession) tryComplete() ([]tss.Envelope, error) {
	if s.completed {
		return nil, nil
	}
	if s.newShare != nil {
		if len(s.confirmations) == len(s.oldKey.state.parties) {
			return nil, s.finalizeConfirmedShare()
		}
		return nil, nil
	}
	if len(s.commits) != len(s.oldKey.state.parties) || len(s.shares) != len(s.oldKey.state.parties) || len(s.newPaillierPubs) != len(s.oldKey.state.parties) || len(s.newRingPedersen) != len(s.oldKey.state.parties) {
		return nil, nil
	}
	order := secp.Order()
	for dealer, share := range s.shares {
		if err := secp.VerifyShare(s.commits[dealer], s.oldKey.state.party, secp.ScalarFromBigInt(share)); err != nil {
			verifyErr := err
			evidenceEnv, evErr := envelope(s.cfg, 1, dealer, s.oldKey.state.party, payloadRefreshShare, nil)
			if evErr != nil {
				return nil, evErr
			}
			return nil, &tss.ProtocolError{
				Code:  tss.ErrCodeVerification,
				Round: 1,
				Party: dealer,
				Blame: newBlame(
					evidenceEnv,
					tss.EvidenceKindRefreshShare,
					"invalid refresh share",
					[]tss.PartyID{dealer},
					rawEvidenceField(evidenceFieldPartiesHash, wireutil.PartySetHash(s.oldKey.state.parties, partySetHashLabel)),
					rawEvidenceField(evidenceFieldCommitmentsHash, wireutil.ByteSlicesHash(refreshCommitmentsHashLabel, s.commits[dealer])),
				),
				Err: verifyErr,
			}
		}
	}
	oldSecret, err := s.oldKey.secretBig()
	if err != nil {
		return nil, err
	}
	newSecret := new(big.Int).Set(oldSecret)
	for _, dealer := range s.oldKey.state.parties {
		newSecret.Add(newSecret, s.shares[dealer])
		newSecret.Mod(newSecret, order)
	}
	newCommitments := make([][]byte, s.cfg.Threshold)
	for degree := 0; degree < s.cfg.Threshold; degree++ {
		points := make([]*secp.Point, 0, len(s.oldKey.state.parties))
		for _, dealer := range s.oldKey.state.parties {
			if len(s.commits[dealer][degree]) == 0 {
				continue
			}
			p, err := secp.PointFromBytes(s.commits[dealer][degree])
			if err != nil {
				return nil, err
			}
			points = append(points, p)
		}
		if degree < len(s.oldKey.state.groupCommitments) {
			if len(s.oldKey.state.groupCommitments[degree]) > 0 {
				oldCommitment, err := secp.PointFromBytes(s.oldKey.state.groupCommitments[degree])
				if err != nil {
					return nil, err
				}
				points = append(points, oldCommitment)
			}
		}
		if len(points) == 0 {
			newCommitments[degree] = nil
			continue
		}
		enc, err := secp.PointBytes(secp.AddPoints(points...))
		if err != nil {
			return nil, err
		}
		newCommitments[degree] = enc
	}
	if !bytes.Equal(newCommitments[0], s.oldKey.state.publicKey) {
		return nil, errors.New("refreshed group public key does not match original")
	}
	verificationShares := make([]VerificationShare, 0, len(s.oldKey.state.parties))
	for _, id := range s.oldKey.state.parties {
		pub, err := secp.EvalCommitments(newCommitments, id)
		if err != nil {
			return nil, err
		}
		enc, err := secp.PointBytes(pub)
		if err != nil {
			return nil, err
		}
		verificationShares = append(verificationShares, VerificationShare{Party: id, PublicKey: enc})
	}
	transcriptHash := s.refreshTranscriptHash(newCommitments)
	localVerificationShare, ok := verificationShareFor(verificationShares, s.oldKey.state.party)
	if !ok {
		return nil, errors.New("missing local verification share")
	}
	shareProof, proofPublic, err := schnorr.Prove(transcriptHash, newSecret)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(proofPublic, localVerificationShare) {
		return nil, errors.New("local share proof public key mismatch")
	}
	shareProofBytes, err := shareProof.MarshalBinary()
	if err != nil {
		return nil, err
	}
	// Construct a temporary share for domain-separated Paillier proof binding.
	localProofShare := &KeyShare{state: &keyShareState{
		party:                  s.oldKey.state.party,
		threshold:              s.cfg.Threshold,
		parties:                s.oldKey.state.parties,
		publicKey:              newCommitments[0],
		paillierPublicKey:      s.newPaillierPubs[s.oldKey.state.party].PublicKey,
		planHash:               append([]byte(nil), s.planHash...),
		keygenTranscriptHash:   transcriptHash,
		paillierProofSessionID: s.cfg.SessionID,
		paillierProofDomain:    domainLabelRefreshPaillier,
	}}
	paillierProof, err := zkpai.ProveModulus(s.cfg.Reader(), keySharePaillierProofDomain(localProofShare), s.newPaillier, s.oldKey.state.party)
	if err != nil {
		return nil, err
	}
	paillierProofBytes, err := zkpai.Marshal(paillierProof)
	if err != nil {
		return nil, err
	}
	newSecretScalar, err := secpSecretScalarFromBig(newSecret)
	if err != nil {
		return nil, err
	}
	s.newShare = &KeyShare{state: &keyShareState{
		version:                tss.Version,
		party:                  s.oldKey.state.party,
		threshold:              s.cfg.Threshold,
		parties:                append([]tss.PartyID(nil), s.oldKey.state.parties...),
		publicKey:              append([]byte(nil), newCommitments[0]...),
		chainCode:              append([]byte(nil), s.oldKey.state.chainCode...),
		secret:                 newSecretScalar,
		groupCommitments:       newCommitments,
		verificationShares:     verificationShares,
		paillierPublicKey:      append([]byte(nil), s.newPaillierPubs[s.oldKey.state.party].PublicKey...),
		paillierPrivateKey:     append([]byte(nil), s.newPaillierPriv...),
		paillierProof:          paillierProofBytes,
		paillierPublicKeys:     s.sortedNewPaillierPublicKeys(),
		ringPedersenParams:     append([]byte(nil), s.newRingPedersen[s.oldKey.state.party].Params...),
		ringPedersenProof:      append([]byte(nil), s.newRingPedersen[s.oldKey.state.party].Proof...),
		ringPedersenPublic:     s.sortedNewRingPedersenPublic(),
		paillierProofSessionID: s.cfg.SessionID,
		paillierProofDomain:    domainLabelRefreshPaillier,
		shareProof:             shareProofBytes,
		planHash:               append([]byte(nil), s.planHash...),
		keygenTranscriptHash:   transcriptHash,
	}}
	// Π^log*: prove that Enc_new(x'_i) and V'_i = x'_i·G share the same secret,
	// using the prover's own Ring-Pedersen parameters for the commitment.
	logCiphertext, logRandomness, err := s.newPaillier.Encrypt(s.cfg.Reader(), newSecret)
	if err != nil {
		return nil, err
	}
	localRP, err := zkpai.UnmarshalRingPedersenParamsWithMaxModulusBits(s.newRingPedersen[s.oldKey.state.party].Params, s.limits.Paillier.MaxModulusBits)
	if err != nil {
		return nil, fmt.Errorf("unmarshal local RP params: %w", err)
	}
	logDomain := logProofDomain(localProofShare, &s.newPaillier.PublicKey, localVerificationShare, transcriptHash)
	verificationPoint, err := secp.PointFromBytes(localVerificationShare)
	if err != nil {
		return nil, fmt.Errorf("invalid verification share: %w", err)
	}
	logStmt := zkpai.LogStarStatement{
		PaillierN:   &s.newPaillier.PublicKey,
		C:           logCiphertext,
		X:           verificationPoint,
		B:           secp.ScalarBaseMult(secp.ScalarFromBigInt(big.NewInt(1))),
		VerifierAux: *localRP,
	}
	logWitness := zkpai.LogStarWitness{
		X:   new(big.Int).Set(newSecret),
		Rho: new(big.Int).Set(logRandomness),
	}
	logProof, err := zkpai.ProveLogStar(zkpai.ActiveSecurityParams(), logDomain, logStmt, logWitness, s.cfg.Reader())
	if err != nil {
		return nil, err
	}
	logProofBytes, err := logProof.MarshalBinary()
	if err != nil {
		return nil, err
	}
	s.newShare.state.logCiphertext = logCiphertext.Bytes()
	s.newShare.state.logProof = logProofBytes
	if err := s.newShare.validateWithoutConfirmations(); err != nil {
		return nil, err
	}
	confirmation, err := s.newShare.KeygenConfirmation()
	if err != nil {
		return nil, err
	}
	encodedConfirmation, err := confirmation.MarshalBinary()
	if err != nil {
		return nil, err
	}
	s.confirmations[s.oldKey.state.party] = append([]byte(nil), encodedConfirmation...)
	confirmationEnv, err := envelope(s.cfg, keygenConfirmationRound, s.oldKey.state.party, 0, payloadKeygenConfirmation, encodedConfirmation)
	if err != nil {
		return nil, err
	}
	out := []tss.Envelope{confirmationEnv}
	s.log.Info(s.cfg.Ctx(), "refresh local material complete",
		"party_id", s.oldKey.state.party,
		"session_id", fmt.Sprintf("%x", s.cfg.SessionID[:8]),
	)
	if len(s.confirmations) == len(s.oldKey.state.parties) {
		if err := s.finalizeConfirmedShare(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *RefreshSession) refreshTranscriptHash(newCommitments [][]byte) []byte {
	t := transcript.New(refreshTranscriptHashLabel)
	t.AppendBytes("session_id", s.cfg.SessionID[:])
	t.AppendBytes("plan_hash", s.planHash)
	t.AppendBytes("old_keygen_transcript_hash", s.oldKey.state.keygenTranscriptHash)
	sortedParties := tss.SortParties(s.oldKey.state.parties)
	t.AppendUint32List("parties", sortedParties)
	t.AppendUint32("threshold", uint32(s.cfg.Threshold))
	t.AppendBytes("public_key", s.oldKey.state.publicKey)
	t.AppendBytes("chain_code", s.oldKey.state.chainCode)
	for _, id := range sortedParties {
		t.AppendUint32("party", id)
		item := s.newPaillierPubs[id]
		t.AppendBytes("paillier_public_key", item.PublicKey)
		t.AppendBytes("paillier_proof", item.Proof)
		rp := s.newRingPedersen[id]
		t.AppendBytes("ring_pedersen_params", rp.Params)
		t.AppendBytes("ring_pedersen_proof", rp.Proof)
	}
	t.AppendBytesList("new_commitments", newCommitments)
	return t.Sum()
}

func validateRefreshCommitments(commitments [][]byte, threshold int) error {
	if len(commitments) == 0 {
		return errors.New("empty refresh commitments")
	}
	if len(commitments) != threshold {
		return fmt.Errorf("got %d commitments, want %d", len(commitments), threshold)
	}
	if len(commitments[0]) != 0 {
		return errors.New("refresh constant commitment must be empty")
	}
	for i, commitment := range commitments {
		if len(commitment) == 0 {
			continue
		}
		if _, err := secp.PointFromBytes(commitment); err != nil {
			return fmt.Errorf("invalid refresh commitment %d: %w", i, err)
		}
	}
	return nil
}

func (s *RefreshSession) sortedNewPaillierPublicKeys() []PaillierPublicShare {
	out := make([]PaillierPublicShare, 0, len(s.oldKey.state.parties))
	for _, id := range s.oldKey.state.parties {
		item := s.newPaillierPubs[id]
		out = append(out, PaillierPublicShare{
			Party:     item.Party,
			PublicKey: append([]byte(nil), item.PublicKey...),
			Proof:     append([]byte(nil), item.Proof...),
		})
	}
	return out
}

func (s *RefreshSession) sortedNewRingPedersenPublic() []RingPedersenPublicShare {
	out := make([]RingPedersenPublicShare, 0, len(s.oldKey.state.parties))
	for _, id := range s.oldKey.state.parties {
		item := s.newRingPedersen[id]
		out = append(out, RingPedersenPublicShare{
			Party:  item.Party,
			Params: append([]byte(nil), item.Params...),
			Proof:  append([]byte(nil), item.Proof...),
		})
	}
	return out
}
