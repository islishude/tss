package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/wire"
	"github.com/islishude/tss/internal/wire/wireutil"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
	"github.com/islishude/tss/internal/zk/schnorr"
)

func (s *ReshareSession) tryComplete() ([]tss.Envelope, error) {
	if s.completed {
		return nil, nil
	}
	if s.newShare != nil {
		if len(s.confirmations) == len(s.newParties) {
			return nil, s.finalizeConfirmedShare()
		}
		return nil, nil
	}
	if len(s.commits) != len(s.dealerParties) {
		return nil, nil
	}
	if !s.isReceiver {
		newCommitments, err := s.aggregateCommitments()
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(newCommitments[0], s.oldPublicKey) {
			return nil, errors.New("reshared group public key does not match original")
		}
		if len(s.confirmations) != len(s.newParties) {
			return nil, nil
		}
		for _, id := range s.newParties {
			raw, ok := s.confirmations[id]
			if !ok {
				return nil, tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, id, fmt.Errorf("missing reshare confirmation from party %d", id))
			}
			confirmation, err := UnmarshalKeygenConfirmation(raw)
			if err != nil {
				return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, keygenConfirmationRound, id, err)
			}
			if err := s.verifyReshareConfirmationForPublicTranscript(confirmation, newCommitments); err != nil {
				return nil, tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, id, err)
			}
		}
		s.completed = true
		return nil, nil
	}
	if len(s.shares) != len(s.dealerParties) || len(s.newPaillierPubs) != len(s.newParties) || len(s.newRingPedersen) != len(s.newParties) {
		return nil, nil
	}
	for dealer, share := range s.shares {
		if err := secp.VerifyShare(s.commits[dealer], uint32(s.selfID), secp.ScalarFromBigInt(share)); err != nil {
			verifyErr := err
			evidenceEnv, evErr := envelope(s.dealerConfig(), 1, dealer, s.selfID, payloadReshareShare, nil, true)
			if evErr != nil {
				return nil, evErr
			}
			return nil, &tss.ProtocolError{
				Code:  tss.ErrCodeVerification,
				Round: 1,
				Party: dealer,
				Blame: newBlame(
					evidenceEnv,
					tss.EvidenceKindReshareShare,
					"invalid reshare share",
					[]tss.PartyID{dealer},
					rawEvidenceField(evidenceFieldPartiesHash, wireutil.PartySetHash(s.dealerParties, partySetHashLabel)),
					rawEvidenceField(evidenceFieldCommitmentsHash, wireutil.ByteSlicesHash(reshareCommitmentsHashLabel, s.commits[dealer])),
				),
				Err: verifyErr,
			}
		}
	}
	order := secp.Order()
	newSecret := new(big.Int)
	for _, dealer := range s.dealerParties {
		newSecret.Add(newSecret, s.shares[dealer])
		newSecret.Mod(newSecret, order)
	}
	newCommitments, err := s.aggregateCommitments()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(newCommitments[0], s.oldPublicKey) {
		return nil, errors.New("reshared group public key does not match original")
	}
	verificationShares := make([]VerificationShare, 0, len(s.newParties))
	for _, id := range s.newParties {
		pub, err := secp.EvalCommitments(newCommitments, uint32(id))
		if err != nil {
			return nil, err
		}
		enc, err := secp.PointBytes(pub)
		if err != nil {
			return nil, err
		}
		verificationShares = append(verificationShares, VerificationShare{Party: id, PublicKey: enc})
	}
	transcriptHash := s.reshareTranscriptHash(newCommitments)
	localVerificationShare, ok := verificationShareFor(verificationShares, s.selfID)
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
	localProofShare := &KeyShare{
		Party:                  s.selfID,
		Threshold:              s.newThreshold,
		Parties:                s.newParties,
		PublicKey:              newCommitments[0],
		PaillierPublicKey:      s.newPaillierPubs[s.selfID].PublicKey,
		KeygenTranscriptHash:   transcriptHash,
		PaillierProofSessionID: s.cfg.SessionID,
		PaillierProofDomain:    domainLabelResharePaillier,
		ResharePlanHash:        s.planHash,
	}
	paillierProof, err := zkpai.ProveModulus(s.cfg.Reader(), keySharePaillierProofDomain(localProofShare), s.newPaillier, uint32(s.selfID))
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
	s.newShare = &KeyShare{
		Version:                tss.Version,
		Party:                  s.selfID,
		Threshold:              s.newThreshold,
		Parties:                append([]tss.PartyID(nil), s.newParties...),
		PublicKey:              append([]byte(nil), newCommitments[0]...),
		ChainCode:              append([]byte(nil), s.oldChainCode...),
		secret:                 newSecretScalar,
		GroupCommitments:       newCommitments,
		VerificationShares:     verificationShares,
		PaillierPublicKey:      append([]byte(nil), s.newPaillierPubs[s.selfID].PublicKey...),
		paillierPrivateKey:     append([]byte(nil), s.newPaillierPriv...),
		PaillierProof:          paillierProofBytes,
		PaillierPublicKeys:     s.sortedNewPaillierPublicKeys(),
		RingPedersenParams:     append([]byte(nil), s.newRingPedersen[s.selfID].Params...),
		RingPedersenProof:      append([]byte(nil), s.newRingPedersen[s.selfID].Proof...),
		RingPedersenPublic:     s.sortedNewRingPedersenPublic(),
		PaillierProofSessionID: s.cfg.SessionID,
		PaillierProofDomain:    domainLabelResharePaillier,
		ResharePlanHash:        append([]byte(nil), s.planHash...),
		ShareProof:             shareProofBytes,
		KeygenTranscriptHash:   transcriptHash,
	}
	logCiphertext, logRandomness, err := s.newPaillier.Encrypt(s.cfg.Reader(), newSecret)
	if err != nil {
		return nil, err
	}
	localRP, err := zkpai.UnmarshalRingPedersenParamsWithMaxModulusBits(s.newRingPedersen[s.selfID].Params, s.limits.Paillier.MaxModulusBits)
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
	s.newShare.LogCiphertext = logCiphertext.Bytes()
	s.newShare.LogProof = logProofBytes
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
	s.confirmations[s.selfID] = append([]byte(nil), encodedConfirmation...)
	confirmationEnv, err := envelope(s.receiverConfig(), keygenConfirmationRound, s.selfID, 0, payloadKeygenConfirmation, encodedConfirmation, false)
	if err != nil {
		return nil, err
	}
	out := []tss.Envelope{confirmationEnv}
	s.log.Info(s.cfg.Ctx(), "reshare local material complete",
		"party_id", s.selfID,
		"session_id", fmt.Sprintf("%x", s.cfg.SessionID[:8]),
	)
	if len(s.confirmations) == len(s.newParties) {
		if err := s.finalizeConfirmedShare(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *ReshareSession) aggregateCommitments() ([][]byte, error) {
	newCommitments := make([][]byte, s.newThreshold)
	for degree := 0; degree < s.newThreshold; degree++ {
		points := make([]*secp.Point, 0, len(s.dealerParties))
		for _, dealer := range s.dealerParties {
			commitment := s.commits[dealer][degree]
			p, err := secp.PointFromBytes(commitment)
			if err != nil {
				return nil, fmt.Errorf("invalid reshare commitment: dealer=%d degree=%d: %w", dealer, degree, err)
			}
			points = append(points, p)
		}
		enc, err := secp.PointBytes(secp.AddPoints(points...))
		if err != nil {
			return nil, err
		}
		newCommitments[degree] = enc
	}
	if len(newCommitments[0]) == 0 {
		return nil, errors.New("reshare produced empty group public key commitment")
	}
	return newCommitments, nil
}

func (s *ReshareSession) reshareTranscriptHash(newCommitments [][]byte) []byte {
	h := sha256.New()
	wire.WriteHashPart(h, []byte(reshareTranscriptHashLabel))
	wire.WriteHashPart(h, []byte(s.plan.CurveID))
	wire.WriteHashPart(h, s.cfg.SessionID[:])
	wire.WriteHashPart(h, s.oldPublicKey)
	wire.WriteHashPart(h, wire.EncodeBytesList(s.plan.OldGroupCommitments))
	wire.WritePartySet(h, s.oldParties)
	wire.WritePartySet(h, s.dealerParties)
	wire.WritePartySet(h, s.newParties)
	wire.WriteHashPart(h, wire.Uint32(uint32(s.plan.OldThreshold)))
	wire.WriteHashPart(h, wire.Uint32(uint32(s.newThreshold)))
	wire.WriteHashPart(h, s.plan.ChainCode)
	wire.WriteHashPart(h, wire.Uint32(uint32(defaultPaillierBits())))
	for _, dealer := range s.oldParties {
		wire.WritePartyID(h, dealer)
		wire.WriteHashPart(h, s.plan.OldVerificationShares[dealer])
	}
	for _, dealer := range s.dealerParties {
		wire.WriteHashPart(h, wire.EncodeBytesList(s.commits[dealer]))
	}
	for _, id := range s.newParties {
		item := s.newPaillierPubs[id]
		wire.WriteHashPart(h, item.PublicKey)
		wire.WriteHashPart(h, item.Proof)
		rp := s.newRingPedersen[id]
		wire.WriteHashPart(h, rp.Params)
		wire.WriteHashPart(h, rp.Proof)
	}
	for _, commitment := range newCommitments {
		wire.WriteHashPart(h, commitment)
	}
	return h.Sum(nil)
}

func (s *ReshareSession) sortedNewPaillierPublicKeys() []PaillierPublicShare {
	out := make([]PaillierPublicShare, 0, len(s.newParties))
	for _, id := range s.newParties {
		item := s.newPaillierPubs[id]
		out = append(out, PaillierPublicShare{
			Party:     item.Party,
			PublicKey: append([]byte(nil), item.PublicKey...),
			Proof:     append([]byte(nil), item.Proof...),
		})
	}
	return out
}

func (s *ReshareSession) sortedNewRingPedersenPublic() []RingPedersenPublicShare {
	out := make([]RingPedersenPublicShare, 0, len(s.newParties))
	for _, id := range s.newParties {
		item := s.newRingPedersen[id]
		out = append(out, RingPedersenPublicShare{
			Party:  item.Party,
			Params: append([]byte(nil), item.Params...),
			Proof:  append([]byte(nil), item.Proof...),
		})
	}
	return out
}
