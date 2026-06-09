package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"slices"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/mta"
	"github.com/islishude/tss/internal/shamir"
	"github.com/islishude/tss/internal/wire"
)

// StartPresignWithContext starts the offline CGGMP-style presign protocol for
// signers and binds the resulting presignature to ctx before nonce generation.
func StartPresignWithContext(key *KeyShare, sessionID tss.SessionID, signers []tss.PartyID, ctx PresignContext) (s *PresignSession, out []tss.Envelope, err error) {
	if err := key.requireMPCMaterial(); err != nil {
		return nil, nil, err
	}
	signers = tss.SortParties(signers)
	if len(signers) < key.Threshold {
		return nil, nil, errors.New("not enough signers")
	}
	if !tss.ContainsParty(signers, key.Party) {
		return nil, nil, errors.New("local party is not in signer set")
	}
	if err := validateSignerSet(key, signers); err != nil {
		return nil, nil, err
	}
	ctx, contextHash, additiveShift, err := preparePresignContext(key, ctx)
	if err != nil {
		return nil, nil, err
	}
	paillierKey, err := key.paillierPrivate()
	if err != nil {
		return nil, nil, err
	}
	// k_i and gamma_i are local nonce scalars. Only Enc(k_i) and Gamma_i leave
	// the process; the raw nonce scalars stay inside the local presign record.
	kShare, err := secp.RandomScalar(nil)
	if err != nil {
		return nil, nil, err
	}
	gamma, err := secp.RandomScalar(nil)
	if err != nil {
		return nil, nil, err
	}
	gammaComm, err := secp.PointBytes(secp.ScalarBaseMult(gamma))
	if err != nil {
		return nil, nil, err
	}
	lambda, err := shamir.LagrangeCoefficient(key.Party, signers, secp.Order())
	if err != nil {
		return nil, nil, err
	}
	sec, err := key.secretBig()
	if err != nil {
		return nil, nil, err
	}
	// xBar is lambda_i*x_i, the signer-set-adjusted secret share used in
	// chi = k*x. The public commitment is derived from the verification share.
	xBar := new(big.Int).Mul(lambda, sec)
	xBar.Mod(xBar, secp.Order())
	kShareSecret, err := newSecpSecretScalar(kShare.Bytes())
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if err != nil {
			kShareSecret.Destroy()
		}
	}()
	gammaSecret, err := newSecpSecretScalar(gamma.Bytes())
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if err != nil {
			gammaSecret.Destroy()
		}
	}()
	xBarSecret, err := secpSecretScalarFromBig(xBar)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if err != nil {
			xBarSecret.Destroy()
		}
	}()
	localVerificationShare, ok := key.verificationShare(key.Party)
	if !ok {
		return nil, nil, errors.New("missing local verification share")
	}
	localVerificationPoint, err := secp.PointFromBytes(localVerificationShare)
	if err != nil {
		return nil, nil, err
	}
	xBarComm, err := secp.PointBytes(secp.ScalarMult(localVerificationPoint, secp.ScalarFromBigInt(lambda)))
	if err != nil {
		return nil, nil, err
	}
	config := tss.ThresholdConfig{Threshold: key.Threshold, Parties: signers, Self: key.Party, SessionID: sessionID}
	// Round 1 publishes Enc_i(k_i); each peer receives a verifier-specific
	// Πenc proof bound to that public payload and the peer's RP parameters.
	startOpening, err := mta.Start(config.Reader(), kShare.BigInt(), &paillierKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	openingReturned := false
	defer func() {
		if !openingReturned {
			startOpening.Destroy()
		}
	}()
	presignPayload := presignRound1Payload{
		Gamma:             gammaComm,
		EncK:              startOpening.Message.Ciphertext,
		PaillierPublicKey: slices.Clone(key.PaillierPublicKey),
	}
	payload, err := marshalPresignRound1Payload(presignPayload)
	if err != nil {
		return nil, nil, err
	}
	publicHash, err := presignRound1PublicHash(presignPayload)
	if err != nil {
		return nil, nil, err
	}
	env, err := envelope(config, 1, key.Party, 0, payloadPresignRound1, payload, false)
	if err != nil {
		return nil, nil, err
	}
	s = &PresignSession{
		key:                  key,
		sessionID:            sessionID,
		config:               config,
		log:                  config.Logger(),
		signers:              signers,
		context:              ctx,
		contextHash:          contextHash,
		additiveShift:        additiveShift,
		paillier:             paillierKey,
		kShare:               kShareSecret,
		gamma:                gammaSecret,
		xBar:                 xBarSecret,
		gammaComm:            gammaComm,
		xBarComm:             xBarComm,
		round1:               map[tss.PartyID]presignRound1Payload{key.Party: presignPayload},
		round1Proofs:         make(map[tss.PartyID]presignRound1ProofPayload),
		round1ProofEnvelopes: make(map[tss.PartyID]tss.Envelope),
		round1Verified:       map[tss.PartyID]bool{key.Party: true},
		round2:               make(map[tss.PartyID]presignRound2Payload),
		deltas:               make(map[tss.PartyID]*big.Int),
		alphaDelta:           make(map[tss.PartyID]*big.Int),
		betaDelta:            make(map[tss.PartyID]*big.Int),
		alphaSigma:           make(map[tss.PartyID]*big.Int),
		betaSigma:            make(map[tss.PartyID]*big.Int),
		startOpening:         startOpening,
	}
	// Defensive: clear local secret scalar references so only session fields
	// own the secrets. The defer guards above will not fire since err is nil.
	// startOpening is kept alive for the per-verifier proof loop below.
	kShareSecret = nil
	gammaSecret = nil
	xBarSecret = nil

	out = []tss.Envelope{env}
	for _, peer := range signers {
		if peer == key.Party {
			continue
		}
		peerRP, err := key.ringPedersenPublicFor(peer)
		if err != nil {
			return nil, nil, err
		}
		proofDomain := mtaStartProofDomain(key, sessionID, signers, key.Party, peer, key.PaillierPublicKey, contextHash)
		proofBytes, err := mta.ProveStartForVerifier(config.Reader(), proofDomain, startOpening, &paillierKey.PublicKey, peerRP)
		if err != nil {
			return nil, nil, err
		}
		proofPayload, err := marshalPresignRound1ProofPayload(presignRound1ProofPayload{
			PublicRound1Hash: publicHash,
			EncKProof:        proofBytes,
		})
		if err != nil {
			return nil, nil, err
		}
		proofEnv, err := envelope(config, 1, key.Party, peer, payloadPresignRound1Proof, proofPayload, true)
		if err != nil {
			return nil, nil, err
		}
		out = append(out, proofEnv)
	}
	// Clear startOpening after all per-verifier proofs are generated.
	// The MtA Finish path in round 2 only uses the Paillier private key and the
	// StartMessage ciphertext — the StartOpening witness (k, rho) is never read
	// after the proofs are generated. Clear it early to reduce the window of
	// secret material exposure.
	startOpening = nil
	s.startOpening = nil

	round2, err := s.tryEmitRound2()
	if err != nil {
		return nil, nil, err
	}
	out = append(out, round2...)
	round3, err := s.tryEmitRound3()
	if err != nil {
		return nil, nil, err
	}
	out = append(out, round3...)
	openingReturned = true
	return s, out, nil
}

// handlePresignRound1 validates and applies a presign round 1 public payload.
//
// Follows the handler template (see doc.go).
func (s *PresignSession) handlePresignRound1(env tss.Envelope) ([]tss.Envelope, error) {
	// ---- 1. PARSE ----
	p, err := unmarshalPresignRound1Payload(env.Payload)
	if err != nil {
		fields := append(keyContextEvidenceFields(s.key), signerEvidenceFields(s.signers)...)
		return nil, protocolErrorWithEvidence(
			tss.ErrCodeInvalidMessage,
			env,
			tss.EvidenceKindPresignRound1,
			"malformed presign round1 payload",
			[]tss.PartyID{env.From},
			err,
			fields...,
		)
	}

	// ---- 2. POLICY VALIDATE ----
	// (round, broadcast, duplicate, transport checks done in dispatcher)

	// ---- 3. CRYPTOGRAPHIC VERIFY ----
	if err := s.validateRound1Public(env.From, p); err != nil {
		return nil, verificationErrorWithEvidence(
			env,
			tss.EvidenceKindPresignRound1,
			"invalid presign round1 public payload",
			[]tss.PartyID{env.From},
			err,
			s.presignRound1EvidenceFields(env.From, p)...,
		)
	}

	// ---- 4. MUTATE STATE ----
	s.round1[env.From] = p

	// ---- 5. EMIT ----
	if err := s.maybeValidateRound1Proof(env.From); err != nil {
		proofEnv := s.round1ProofEnvelopes[env.From]
		return nil, verificationErrorWithEvidence(
			proofEnv,
			tss.EvidenceKindPresignRound1,
			"invalid presign round1 proof",
			[]tss.PartyID{env.From},
			err,
			s.presignRound1ProofEvidenceFields(env.From, p, s.round1Proofs[env.From])...,
		)
	}
	return s.tryEmitRound2()
}

// handlePresignRound1Proof validates and applies a presign round 1 proof payload.
//
// Follows the handler template (see doc.go).
func (s *PresignSession) handlePresignRound1Proof(env tss.Envelope) ([]tss.Envelope, error) {
	// ---- 1. PARSE ----
	p, err := unmarshalPresignRound1ProofPayload(env.Payload)
	if err != nil {
		fields := append(keyContextEvidenceFields(s.key), signerEvidenceFields(s.signers)...)
		return nil, protocolErrorWithEvidence(
			tss.ErrCodeInvalidMessage,
			env,
			tss.EvidenceKindPresignRound1,
			"malformed presign round1 proof payload",
			[]tss.PartyID{env.From},
			err,
			fields...,
		)
	}

	// ---- 2. POLICY VALIDATE ----
	// (round, direct-confidential, self-send, duplicate checks done in dispatcher)

	// ---- 3. CRYPTOGRAPHIC VERIFY ----
	// (deferred until both public and proof are available — see maybeValidateRound1Proof)

	// ---- 4. MUTATE STATE ----
	s.round1Proofs[env.From] = p
	s.round1ProofEnvelopes[env.From] = env

	// ---- 5. EMIT ----
	if err := s.maybeValidateRound1Proof(env.From); err != nil {
		public := s.round1[env.From]
		return nil, verificationErrorWithEvidence(
			env,
			tss.EvidenceKindPresignRound1,
			"invalid presign round1 proof",
			[]tss.PartyID{env.From},
			err,
			s.presignRound1ProofEvidenceFields(env.From, public, p)...,
		)
	}
	return s.tryEmitRound2()
}

func (s *PresignSession) presignRound1EvidenceFields(from tss.PartyID, p presignRound1Payload) []tss.EvidenceField {
	fields := append(keyContextEvidenceFields(s.key), signerEvidenceFields(s.signers)...)
	publicHash, _ := presignRound1PublicHash(p)
	fields = append(fields,
		hashEvidenceField(evidenceFieldObservedPaillierKeyHash, p.PaillierPublicKey),
		rawEvidenceField("round1_public_hash", publicHash),
		hashEvidenceField("gamma_hash", p.Gamma),
		hashEvidenceField("enc_k_hash", p.EncK),
	)
	if expected, err := s.key.paillierPublicFor(from); err == nil {
		if encoded, err := expected.MarshalBinary(); err == nil {
			fields = append(fields, hashEvidenceField(evidenceFieldExpectedPaillierKeyHash, encoded))
		}
	}
	return fields
}

func (s *PresignSession) presignRound1ProofEvidenceFields(from tss.PartyID, public presignRound1Payload, proof presignRound1ProofPayload) []tss.EvidenceField {
	fields := s.presignRound1EvidenceFields(from, public)
	return append(fields,
		rawEvidenceField("proof_public_round1_hash", proof.PublicRound1Hash),
		hashEvidenceField("enc_k_proof_hash", proof.EncKProof),
	)
}

func (s *PresignSession) validateRound1Public(from tss.PartyID, p presignRound1Payload) error {
	if _, err := secp.PointFromBytes(p.Gamma); err != nil {
		return fmt.Errorf("invalid gamma: %w", err)
	}
	expectedPK, err := s.key.paillierPublicFor(from)
	if err != nil {
		return err
	}
	expectedPKBytes, err := expectedPK.MarshalBinary()
	if err != nil {
		return err
	}
	if !bytes.Equal(expectedPKBytes, p.PaillierPublicKey) {
		return errors.New("round1 Paillier public key does not match keygen")
	}
	ciphertext := new(big.Int).SetBytes(p.EncK)
	if err := expectedPK.ValidateCiphertext(ciphertext); err != nil {
		return fmt.Errorf("invalid encrypted nonce ciphertext: %w", err)
	}
	return nil
}

func (s *PresignSession) maybeValidateRound1Proof(from tss.PartyID) error {
	if from == s.key.Party {
		s.round1Verified[from] = true
		return nil
	}
	if s.round1Verified[from] {
		return nil
	}
	public, havePublic := s.round1[from]
	proof, haveProof := s.round1Proofs[from]
	if !havePublic || !haveProof {
		return nil
	}
	if err := s.validateRound1Proof(from, public, proof); err != nil {
		return err
	}
	s.round1Verified[from] = true
	return nil
}

func (s *PresignSession) validateRound1Proof(from tss.PartyID, public presignRound1Payload, proof presignRound1ProofPayload) error {
	publicHash, err := presignRound1PublicHash(public)
	if err != nil {
		return err
	}
	if !bytes.Equal(publicHash, proof.PublicRound1Hash) {
		return errors.New("presign round1 proof public hash mismatch")
	}
	proverPK, err := s.key.paillierPublicFor(from)
	if err != nil {
		return err
	}
	localRP, err := s.key.ringPedersenPublicFor(s.key.Party)
	if err != nil {
		return err
	}
	start := mta.StartMessage{Ciphertext: public.EncK}
	domain := mtaStartProofDomain(s.key, s.sessionID, s.signers, from, s.key.Party, public.PaillierPublicKey, s.contextHash)
	return mta.VerifyStart(domain, start, proverPK, localRP, proof.EncKProof)
}

func presignRound1PublicHash(p presignRound1Payload) ([]byte, error) {
	payload, err := marshalPresignRound1Payload(p)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	wire.WriteHashPart(h, []byte(presignRound1PublicLabel))
	wire.WriteHashPart(h, payload)
	return h.Sum(nil), nil
}
