package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/bip32util"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/transcript"
	"github.com/islishude/tss/internal/wire/wireutil"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
	"github.com/islishude/tss/internal/zk/schnorr"
)

func (s *KeygenSession) tryComplete() ([]tss.Envelope, error) {
	if s.completed {
		return nil, nil
	}
	if s.pending != nil {
		if len(s.confirmations) == len(s.cfg.Parties) {
			return nil, s.finalizeConfirmedKeyShare()
		}
		return nil, nil
	}
	if len(s.commits) != len(s.cfg.Parties) || len(s.shares) != len(s.cfg.Parties) || len(s.paillierPubs) != len(s.cfg.Parties) || len(s.chainCodeComms) != len(s.cfg.Parties) || len(s.ringPedersen) != len(s.cfg.Parties) {
		return nil, nil
	}
	order := secp.Order()
	for dealer, share := range s.shares {
		if err := secp.VerifyShare(s.commits[dealer], s.cfg.Self, secp.ScalarFromBigInt(share)); err != nil {
			s.log.Warn(s.cfg.Ctx(), "invalid DKG share",
				"party_id", s.cfg.Self,
				"dealer", dealer,
			)
			protoErr, evErr := s.buildShareVerificationBlame(dealer, s.commits[dealer], err)
			if evErr != nil {
				return nil, evErr
			}
			return nil, protoErr
		}
	}
	secret := new(big.Int)
	for _, dealer := range s.cfg.Parties {
		secret.Add(secret, s.shares[dealer])
		secret.Mod(secret, order)
	}
	// Chain code is aggregated from round 2 confirmation reveals (commit-reveal).
	groupCommitments := make([][]byte, s.cfg.Threshold)
	for degree := 0; degree < s.cfg.Threshold; degree++ {
		points := make([]*secp.Point, 0, len(s.cfg.Parties))
		for _, dealer := range s.cfg.Parties {
			p, err := secp.PointFromBytes(s.commits[dealer][degree])
			if err != nil {
				return nil, err
			}
			points = append(points, p)
		}
		enc, err := secp.PointBytes(secp.AddPoints(points...))
		if err != nil {
			return nil, err
		}
		groupCommitments[degree] = enc
	}
	verificationShares := make([]VerificationShare, 0, len(s.cfg.Parties))
	for _, id := range s.cfg.Parties {
		pub, err := secp.EvalCommitments(groupCommitments, id)
		if err != nil {
			return nil, err
		}
		enc, err := secp.PointBytes(pub)
		if err != nil {
			return nil, err
		}
		verificationShares = append(verificationShares, VerificationShare{Party: id, PublicKey: enc})
	}
	transcriptHash := s.keygenTranscriptHash(groupCommitments)
	localVerificationShare, ok := verificationShareFor(verificationShares, s.cfg.Self)
	if !ok {
		return nil, errors.New("missing local verification share")
	}
	shareProof, proofPublic, err := schnorr.Prove(transcriptHash, secret)
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
	localPaillierPub, err := s.paillier.PublicKey.MarshalBinary()
	if err != nil {
		return nil, err
	}
	localPaillierPriv, err := s.paillier.MarshalBinary()
	if err != nil {
		return nil, err
	}
	localProofShare := &KeyShare{state: &keyShareState{
		securityParams:         s.securityParams,
		party:                  s.cfg.Self,
		threshold:              s.cfg.Threshold,
		parties:                s.cfg.Parties,
		publicKey:              groupCommitments[0],
		paillierPublicKey:      localPaillierPub,
		planHash:               append([]byte(nil), s.planHash...),
		keygenTranscriptHash:   transcriptHash,
		paillierProofSessionID: s.cfg.SessionID,
		paillierProofDomain:    domainLabelKeygenModulus,
	}}
	localPaillierProof, err := zkpai.ProveModulus(s.cfg.Reader(), keySharePaillierProofDomain(localProofShare), s.paillier, s.cfg.Self)
	if err != nil {
		return nil, err
	}
	localPaillierProofBytes, err := zkpai.Marshal(localPaillierProof)
	if err != nil {
		return nil, err
	}
	localRingPedersen := s.ringPedersen[s.cfg.Self]
	secretScalar, err := secpSecretScalarFromBig(secret)
	if err != nil {
		return nil, err
	}
	share := &KeyShare{state: &keyShareState{
		version:                tss.Version,
		securityParams:         s.securityParams,
		party:                  s.cfg.Self,
		threshold:              s.cfg.Threshold,
		parties:                s.cfg.Parties.Clone(),
		publicKey:              append([]byte(nil), groupCommitments[0]...),
		chainCode:              nil, // filled in after confirmation round
		secret:                 secretScalar,
		groupCommitments:       groupCommitments,
		verificationShares:     verificationShares,
		paillierPublicKey:      localPaillierPub,
		paillierPrivateKey:     localPaillierPriv,
		paillierProof:          localPaillierProofBytes,
		paillierPublicKeys:     s.sortedPaillierPublicKeys(),
		ringPedersenParams:     append([]byte(nil), localRingPedersen.Params...),
		ringPedersenProof:      append([]byte(nil), localRingPedersen.Proof...),
		ringPedersenPublic:     s.sortedRingPedersenPublic(),
		paillierProofSessionID: s.cfg.SessionID,
		paillierProofDomain:    domainLabelKeygenModulus,
		shareProof:             shareProofBytes,
		planHash:               append([]byte(nil), s.planHash...),
		keygenTranscriptHash:   transcriptHash,
	}}
	// Π^log*: prove that Enc_i(x_i) and V_i = x_i·G share the same secret x_i,
	// using the prover's own Ring-Pedersen parameters for the commitment.
	logCiphertext, logRandomness, err := s.paillier.Encrypt(s.cfg.Reader(), secret)
	if err != nil {
		return nil, err
	}
	localRP, err := zkpai.UnmarshalRingPedersenParamsWithMaxModulusBits(localRingPedersen.Params, s.limits.Paillier.MaxModulusBits)
	if err != nil {
		return nil, fmt.Errorf("unmarshal local RP params: %w", err)
	}
	logDomain := logProofDomain(localProofShare, &s.paillier.PublicKey, localVerificationShare, transcriptHash)
	verificationPoint, err := secp.PointFromBytes(localVerificationShare)
	if err != nil {
		return nil, fmt.Errorf("invalid verification share: %w", err)
	}
	logStmt := zkpai.LogStarStatement{
		PaillierN:   &s.paillier.PublicKey,
		C:           logCiphertext,
		X:           verificationPoint,
		B:           secp.ScalarBaseMult(secp.ScalarFromBigInt(big.NewInt(1))), // G
		VerifierAux: *localRP,
	}
	logWitness := zkpai.LogStarWitness{
		X:   new(big.Int).Set(secret),
		Rho: new(big.Int).Set(logRandomness),
	}
	logProof, err := zkpai.ProveLogStar(s.securityParams, logDomain, logStmt, logWitness, s.cfg.Reader())
	if err != nil {
		return nil, err
	}
	logProofBytes, err := logProof.MarshalBinary()
	if err != nil {
		return nil, err
	}
	share.state.logCiphertext = logCiphertext.Bytes()
	share.state.logProof = logProofBytes
	// Carry the local chain code into the confirmation for commit-reveal.
	share.state.chainCode = append([]byte(nil), s.chainCodes[s.cfg.Self]...)
	if err := share.validateWithoutConfirmations(s.limits); err != nil {
		return nil, err
	}
	confirmation, err := share.KeygenConfirmationWithLimits(s.limits)
	if err != nil {
		return nil, err
	}
	encodedConfirmation, err := confirmation.MarshalBinary()
	// Don't leak the per-party chain code into the KeyShare — overwritten with aggregate after confirmations.
	share.state.chainCode = nil
	if err != nil {
		return nil, err
	}
	s.confirmations[s.cfg.Self] = append([]byte(nil), encodedConfirmation...)
	s.pending = &pendingKeyShare{share: share}
	s.state = keygenConfirming
	confirmationEnv, err := newEnvelope(s.cfg, keygenConfirmationRound, s.cfg.Self, tss.BroadcastPartyId, payloadKeygenConfirmation, encodedConfirmation)
	if err != nil {
		return nil, err
	}
	out := []tss.Envelope{confirmationEnv}
	pubKeyHash := sha256.Sum256(groupCommitments[0])
	s.log.Info(s.cfg.Ctx(), "keygen local material complete",
		"party_id", s.cfg.Self,
		"session_id", fmt.Sprintf("%x", s.cfg.SessionID[:8]),
		"public_key_hash", fmt.Sprintf("%x", pubKeyHash[:8]),
	)
	if len(s.confirmations) == len(s.cfg.Parties) {
		if err := s.finalizeConfirmedKeyShare(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// buildShareVerificationBlame constructs a ProtocolError with blame evidence
// for a DKG share that fails verification against the sender's polynomial
// commitments. Callers are responsible for logging the failure with the
// appropriate path-specific context (eager or deferred).
func (s *KeygenSession) buildShareVerificationBlame(dealer tss.PartyID, commits [][]byte, verifyErr error) (*tss.ProtocolError, error) {
	evidenceEnv, evErr := newEnvelope(s.cfg, 1, dealer, s.cfg.Self, payloadKeygenShare, nil)
	if evErr != nil {
		return nil, evErr
	}
	return &tss.ProtocolError{
		Code:  tss.ErrCodeVerification,
		Round: 1,
		Party: dealer,
		Blame: newBlame(
			evidenceEnv,
			tss.EvidenceKindKeygenShare,
			"invalid DKG share",
			tss.NewPartySet(dealer),
			rawEvidenceField(evidenceFieldPartiesHash, wireutil.PartySetHash(s.cfg.Parties, partySetHashLabel)),
			rawEvidenceField(evidenceFieldCommitmentsHash, wireutil.ByteSlicesHash(keygenCommitmentsHashLabel, commits)),
		),
		Err: verifyErr,
	}, nil
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
	clearBigIntMap(s.shares)
	for id, chainCode := range s.chainCodes {
		clear(chainCode)
		delete(s.chainCodes, id)
	}
	if s.paillier != nil {
		s.paillier.Destroy()
		s.paillier = nil
	}
	if s.pending != nil && s.pending.share != nil {
		s.pending.share.Destroy()
	}
	s.pending = nil
}

func (s *KeygenSession) sortedPaillierPublicKeys() []PaillierPublicShare {
	out := make([]PaillierPublicShare, 0, len(s.cfg.Parties))
	for _, id := range s.cfg.Parties {
		item := s.paillierPubs[id]
		out = append(out, item.Clone())
	}
	return out
}

func (s *KeygenSession) sortedRingPedersenPublic() []RingPedersenPublicShare {
	out := make([]RingPedersenPublicShare, 0, len(s.cfg.Parties))
	for _, id := range s.cfg.Parties {
		item := s.ringPedersen[id]
		out = append(out, item.Clone())
	}
	return out
}

func (s *KeygenSession) keygenTranscriptHash(groupCommitments [][]byte) []byte {
	t := transcript.New(keygenTranscriptHashLabel)
	t.AppendBytes("session_id", s.cfg.SessionID[:])
	t.AppendBytes("plan_hash", s.planHash)
	for _, id := range tss.SortParties(s.cfg.Parties) {
		t.AppendUint32("party", id)
		t.AppendBytesList("commitments", s.commits[id])
		item := s.paillierPubs[id]
		t.AppendBytes("paillier_public_key", item.PublicKey)
		t.AppendBytes("paillier_proof", item.Proof)
		rp := s.ringPedersen[id]
		t.AppendBytes("ring_pedersen_params", rp.Params)
		t.AppendBytes("ring_pedersen_proof", rp.Proof)
		t.AppendBytes("chain_code_commitment", s.chainCodeComms[id])
	}
	t.AppendBytesList("group_commitments", groupCommitments)
	return t.Sum()
}

func verificationShareFor(shares []VerificationShare, id tss.PartyID) ([]byte, bool) {
	for _, share := range shares {
		if share.Party == id {
			return share.PublicKey, true
		}
	}
	return nil, false
}

const cggmpChainCodeCommitLabel = "cggmp21-secp256k1-chain-code-commit-v1"

// cggmpChainCodeCommit produces a hash commitment for a party's HD chain code.
// The chain code is revealed in round 2 (keygen confirmation) to prevent last-sender bias.
func cggmpChainCodeCommit(sessionID tss.SessionID, partyID tss.PartyID, chainCode []byte) []byte {
	t := transcript.New(cggmpChainCodeCommitLabel)
	t.AppendBytes("session_id", sessionID[:])
	t.AppendUint32("party_id", partyID)
	t.AppendBytes("chain_code", chainCode)
	return t.Sum()
}

// verifyCGGMPChainCodeCommit checks that a revealed chain code matches its round 1 commit.
func verifyCGGMPChainCodeCommit(sessionID tss.SessionID, partyID tss.PartyID, chainCode, commit []byte) bool {
	if len(commit) != sha256.Size || len(chainCode) != bip32util.ChainCodeSize {
		return false
	}
	expected := cggmpChainCodeCommit(sessionID, partyID, chainCode)
	return bytes.Equal(expected, commit)
}
