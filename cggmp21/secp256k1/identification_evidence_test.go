package secp256k1

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/islishude/tss"
)

type evidenceEnvelopeSigner struct{ private ed25519.PrivateKey }

func (s evidenceEnvelopeSigner) SignEnvelopeDigest(digest [32]byte) ([]byte, error) {
	return ed25519.Sign(s.private, digest[:]), nil
}

type evidenceEnvelopeVerifier struct{ public ed25519.PublicKey }

func (v evidenceEnvelopeVerifier) VerifyEnvelopeSignature(party tss.PartyID, digest [32]byte, signature []byte) error {
	if party != 2 || !ed25519.Verify(v.public, digest[:], signature) {
		return errors.New("invalid evidence envelope signature")
	}
	return nil
}

type acceptingEvidenceEnvelopeVerifier struct{}

func (acceptingEvidenceEnvelopeVerifier) VerifyEnvelopeSignature(tss.PartyID, [32]byte, []byte) error {
	return nil
}

type acceptingIdentificationVerifier struct{ calls int }

func (v *acceptingIdentificationVerifier) VerifyIdentificationFailure(evidence tss.BlameEvidence, record tss.IdentificationRecord) error {
	if evidence.From != record.Accused || record.FailureClass != "sign-identification-invalid-proof" {
		return errors.New("unexpected identification accusation")
	}
	v.calls++
	return nil
}

type identificationVerifierFunc func(tss.BlameEvidence, tss.IdentificationRecord) error

func (f identificationVerifierFunc) VerifyIdentificationFailure(evidence tss.BlameEvidence, record tss.IdentificationRecord) error {
	return f(evidence, record)
}

func TestVerifyBlameEvidenceProofBackedIdentificationRecord(t *testing.T) {
	t.Parallel()
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	parties := tss.NewPartySet(1, 2)
	keygenHash := bytes.Repeat([]byte{0x31}, 32)
	presignHash := bytes.Repeat([]byte{0x32}, 32)
	protocolAlert := bytes.Repeat([]byte{0x33}, 32)
	env, err := tss.NewEnvelope(tss.EnvelopeInput{
		Protocol: tss.ProtocolCGGMP21Secp256k1, SessionID: sessionID,
		Round: signIdentificationRound, From: 2, PayloadType: payloadSignIdentification,
		Payload: []byte("public-invalid-identification-proof"),
	})
	if err != nil {
		t.Fatal(err)
	}
	recordField, err := identificationProofEvidenceField(env, "sign-identification-invalid-proof", protocolAlert, keygenHash, presignHash)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := tss.NewBlameEvidence(env, tss.EvidenceKindSignIdentification, "invalid sign identification proof", []tss.EvidenceField{
		rawEvidenceField(evidenceFieldPartiesHash, tss.PartySetHash(parties, partySetHashLabel)),
		rawEvidenceField(evidenceFieldSignerSetHash, tss.PartySetHash(parties, partySetHashLabel)),
		rawEvidenceField(evidenceFieldKeygenTranscriptHash, keygenHash),
		rawEvidenceField(evidenceFieldPresignTranscriptHash, presignHash),
		recordField,
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := evidence.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	verifier := &acceptingIdentificationVerifier{}
	ctx := EvidenceContext{
		SessionID: sessionID, Parties: parties, Signers: parties,
		KeygenTranscriptHash: keygenHash, PresignTranscriptHash: presignHash,
		IdentificationVerifier: verifier,
	}
	if err := VerifyBlameEvidence(encoded, ctx); err != nil {
		t.Fatal(err)
	}
	if verifier.calls != 1 {
		t.Fatalf("identification verifier called %d times, want 1", verifier.calls)
	}

	mutations := []func(*tss.IdentificationRecord){
		func(r *tss.IdentificationRecord) { r.Accused = 1 },
		func(r *tss.IdentificationRecord) { r.Statement[0] ^= 1 },
		func(r *tss.IdentificationRecord) { r.Proof[0] ^= 1 },
		func(r *tss.IdentificationRecord) { r.TranscriptHashes[0].Value[0] ^= 1 },
	}
	for i, mutate := range mutations {
		candidate := *evidence
		candidate.PublicInputs = make([]tss.EvidenceField, len(evidence.PublicInputs))
		for j := range evidence.PublicInputs {
			candidate.PublicInputs[j] = evidence.PublicInputs[j].Clone()
		}
		rawRecord, ok := candidate.Field(tss.IdentificationRecordEvidenceKey)
		if !ok {
			t.Fatal("missing identification record")
		}
		var record tss.IdentificationRecord
		if err := record.UnmarshalBinary(rawRecord); err != nil {
			t.Fatal(err)
		}
		mutate(&record)
		alert := record.ComputeAlertDigest()
		record.AlertDigest = alert[:]
		encodedRecord, err := record.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		for j := range candidate.PublicInputs {
			if candidate.PublicInputs[j].Key == tss.IdentificationRecordEvidenceKey {
				candidate.PublicInputs[j].Value = encodedRecord
			}
		}
		candidateBytes, err := candidate.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyBlameEvidence(candidateBytes, ctx); err == nil {
			t.Fatalf("identification record mutation %d verified", i)
		}
	}
}

func TestVerifyBlameEvidenceSignedRound2Equivocation(t *testing.T) {
	t.Parallel()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	newSigned := func(payload string) tss.Envelope {
		env, err := tss.NewEnvelope(tss.EnvelopeInput{
			Protocol: tss.ProtocolCGGMP21Secp256k1, SessionID: sessionID,
			Round: presignRound2, From: 2, To: 1, PayloadType: payloadPresignRound2,
			Payload: []byte(payload),
		})
		if err != nil {
			t.Fatal(err)
		}
		signed, err := tss.SignEnvelope(env, evidenceEnvelopeSigner{private: private})
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}
	first, second := newSigned("first"), newSigned("second")
	firstRaw, err := first.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	secondRaw, err := second.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	parties := tss.NewPartySet(1, 2)
	keygenHash := bytes.Repeat([]byte{0x41}, 32)
	record := &tss.IdentificationRecord{
		FailureClass: "presign_round2_signed_equivocation", Accused: 2,
		SignedEnvelopeA: firstRaw, SignedEnvelopeB: secondRaw,
		TranscriptHashes: []tss.EvidenceField{
			rawEvidenceField(evidenceFieldKeygenTranscriptHash, keygenHash),
			rawEvidenceField(evidenceFieldSignerSetHash, tss.PartySetHash(parties, partySetHashLabel)),
		},
	}
	alert := record.ComputeAlertDigest()
	record.AlertDigest = alert[:]
	recordField, err := tss.IdentificationEvidenceField(record)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := tss.NewBlameEvidence(first, tss.EvidenceKindPresignRound2, "signed presign round2 equivocation", []tss.EvidenceField{
		rawEvidenceField(evidenceFieldPartiesHash, tss.PartySetHash(parties, partySetHashLabel)),
		rawEvidenceField(evidenceFieldSignerSetHash, tss.PartySetHash(parties, partySetHashLabel)),
		rawEvidenceField(evidenceFieldKeygenTranscriptHash, keygenHash),
		recordField,
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := evidence.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	ctx := EvidenceContext{
		SessionID: sessionID, Parties: parties, Signers: parties,
		KeygenTranscriptHash: keygenHash, EnvelopeVerifier: evidenceEnvelopeVerifier{public: public},
	}
	if err := VerifyBlameEvidence(encoded, ctx); err != nil {
		t.Fatal(err)
	}

	tampered := record.Clone()
	tampered.SignedEnvelopeB[len(tampered.SignedEnvelopeB)-1] ^= 1
	alert = tampered.ComputeAlertDigest()
	tampered.AlertDigest = alert[:]
	tamperedField, err := tss.IdentificationEvidenceField(&tampered)
	if err != nil {
		t.Fatal(err)
	}
	for i := range evidence.PublicInputs {
		if evidence.PublicInputs[i].Key == tss.IdentificationRecordEvidenceKey {
			evidence.PublicInputs[i] = tamperedField
		}
	}
	tamperedEvidence, err := evidence.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBlameEvidence(tamperedEvidence, ctx); err == nil {
		t.Fatal("verified tampered signed equivocation evidence")
	}
}

func TestVerifyBlameEvidenceRejectsResignedIdenticalEnvelope(t *testing.T) {
	t.Parallel()
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	first, err := tss.NewEnvelope(tss.EnvelopeInput{
		Protocol: tss.ProtocolCGGMP21Secp256k1, SessionID: sessionID,
		Round: presignRound2, From: 2, To: 1, PayloadType: payloadPresignRound2,
		Payload: []byte("same signed content"), SenderSignature: []byte{1},
	})
	if err != nil {
		t.Fatal(err)
	}
	second := first.Clone()
	second.SenderSignature = []byte{2}
	firstRaw, err := first.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	secondRaw, err := second.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	record := &tss.IdentificationRecord{
		FailureClass: "presign_round2_signed_equivocation", Accused: 2,
		SignedEnvelopeA: firstRaw, SignedEnvelopeB: secondRaw,
	}
	alert := record.ComputeAlertDigest()
	record.AlertDigest = alert[:]
	recordField, err := tss.IdentificationEvidenceField(record)
	if err != nil {
		t.Fatal(err)
	}
	parties := tss.NewPartySet(1, 2)
	evidence, err := tss.NewBlameEvidence(first, tss.EvidenceKindPresignRound2, "signed equivocation", []tss.EvidenceField{
		rawEvidenceField(evidenceFieldPartiesHash, tss.PartySetHash(parties, partySetHashLabel)),
		recordField,
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := evidence.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	err = VerifyBlameEvidence(encoded, EvidenceContext{
		SessionID: sessionID, Parties: parties,
		EnvelopeVerifier: acceptingEvidenceEnvelopeVerifier{},
	})
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("identical")) {
		t.Fatalf("resigned identical envelope verification = %v, want identical-content rejection", err)
	}
	if !sameEnvelopeSigningContent(firstRaw, secondRaw) {
		t.Fatal("round3 content comparison treated signature bytes as envelope content")
	}
}

func TestBindInboundAuthenticationEvidencePreservesCrossEnvelopeRecord(t *testing.T) {
	t.Parallel()
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	direct, err := tss.NewEnvelope(tss.EnvelopeInput{
		Protocol: tss.ProtocolCGGMP21Secp256k1, SessionID: sessionID,
		Round: presignRound2, From: 2, To: 1, PayloadType: payloadPresignRound2,
		Payload: []byte("accused direct envelope"), SenderSignature: []byte{1},
	})
	if err != nil {
		t.Fatal(err)
	}
	recordField, err := signedFailureEvidenceField(direct, tss.EvidenceKindPresignRound2, nil)
	if err != nil {
		t.Fatal(err)
	}
	original := verificationErrorWithEvidence(direct, tss.EvidenceKindPresignRound2, "cross-envelope failure", tss.NewPartySet(2), errors.New("invalid view"), recordField)

	report, err := tss.NewEnvelope(tss.EnvelopeInput{
		Protocol: tss.ProtocolCGGMP21Secp256k1, SessionID: sessionID,
		Round: presignRound3, From: 1, PayloadType: payloadPresignRound3,
		Payload: []byte("reporting broadcast"),
	})
	if err != nil {
		t.Fatal(err)
	}
	payloadHash := sha256.Sum256(report.Payload)
	reportDigest := report.Digest()
	acks := []tss.BroadcastAck{
		{Party: 1, PayloadHash: payloadHash, EnvelopeDigest: reportDigest},
		{Party: 2, PayloadHash: payloadHash, EnvelopeDigest: reportDigest},
	}
	certificate, err := tss.NewBroadcastCertificate(report, tss.NewPartySet(1, 2), acks)
	if err != nil {
		t.Fatal(err)
	}
	reportRaw, err := report.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	inbound, err := tss.OpenEnvelope(reportRaw, tss.ReceiveInfo{Peer: 1, Protection: tss.ChannelPlaintext}, tss.WithBroadcastCertificate(certificate))
	if err != nil {
		t.Fatal(err)
	}
	boundErr := bindInboundAuthenticationEvidence(original, inbound)
	var protocolErr *tss.ProtocolError
	if !errors.As(boundErr, &protocolErr) || protocolErr.Blame == nil {
		t.Fatalf("bound error = %v, want blame", boundErr)
	}
	evidence, err := tss.DecodeBinary[tss.BlameEvidence](protocolErr.Blame.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	recordRaw, ok := evidence.Field(tss.IdentificationRecordEvidenceKey)
	if !ok {
		t.Fatal("bound evidence omitted identification record")
	}
	var record tss.IdentificationRecord
	if err := record.UnmarshalBinary(recordRaw); err != nil {
		t.Fatal(err)
	}
	directRaw, err := direct.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(record.SignedEnvelopeA, directRaw) || len(record.BroadcastCertificate) != 0 {
		t.Fatal("cross-envelope certificate binding replaced the accused direct envelope")
	}
}

func TestIdentificationPayloadSizeLimit(t *testing.T) {
	t.Parallel()
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	env, err := tss.NewEnvelope(tss.EnvelopeInput{
		Protocol: tss.ProtocolCGGMP21Secp256k1, SessionID: sessionID,
		Round: signIdentificationRound, From: 2, PayloadType: payloadSignIdentification,
		Payload: make([]byte, maxIdentificationPayloadBytes+1),
	})
	if err != nil {
		t.Fatal(err)
	}
	err = validateIdentificationPayloadSize(env)
	var protocolErr *tss.ProtocolError
	if !errors.As(err, &protocolErr) || protocolErr.Code != tss.ErrCodePayloadTooLarge || protocolErr.Blame != nil {
		t.Fatalf("oversized identification payload = %v, want unblamed payload limit", err)
	}
	env.Payload = env.Payload[:maxIdentificationPayloadBytes]
	if err := validateIdentificationPayloadSize(env); err != nil {
		t.Fatalf("boundary identification payload rejected: %v", err)
	}
}

func TestCertifiedBroadcastFailureCarriesPortableCertificate(t *testing.T) {
	t.Parallel()
	parties := tss.NewPartySet(1, 2)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	env, err := tss.NewEnvelope(tss.EnvelopeInput{
		Protocol: tss.ProtocolCGGMP21Secp256k1, SessionID: sessionID,
		Round: signIdentificationRound, From: 2, PayloadType: payloadSignIdentification,
		Payload: []byte("invalid certified identification payload"),
	})
	if err != nil {
		t.Fatal(err)
	}

	publicKeys := make(map[tss.PartyID]ed25519.PublicKey, len(parties))
	acks := make([]tss.BroadcastAck, 0, len(parties))
	for _, party := range parties {
		publicKey, privateKey, keyErr := ed25519.GenerateKey(rand.Reader)
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		publicKeys[party] = publicKey
		signer := tss.NewInMemoryAckSigner(party, func(digest [32]byte) ([]byte, error) {
			return ed25519.Sign(privateKey, digest[:]), nil
		})
		ack, signErr := tss.SignBroadcastAck(env, party, signer)
		if signErr != nil {
			t.Fatal(signErr)
		}
		acks = append(acks, ack)
	}
	certificate, err := tss.NewBroadcastCertificate(env, parties, acks)
	if err != nil {
		t.Fatal(err)
	}
	rawEnvelope, err := env.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	inbound, err := tss.OpenEnvelope(rawEnvelope, tss.ReceiveInfo{Peer: env.From, Protection: tss.ChannelPlaintext}, tss.WithBroadcastCertificate(certificate))
	if err != nil {
		t.Fatal(err)
	}

	protocolErr := verificationErrorWithEvidence(env, tss.EvidenceKindSignIdentification, "invalid certified identification proof", parties, errors.New("invalid proof"),
		rawEvidenceField(evidenceFieldPartiesHash, tss.PartySetHash(parties, partySetHashLabel)),
		rawEvidenceField(evidenceFieldSignerSetHash, tss.PartySetHash(parties, partySetHashLabel)))
	boundErr := bindInboundAuthenticationEvidence(protocolErr, inbound)
	var bound *tss.ProtocolError
	if !errors.As(boundErr, &bound) || bound.Blame == nil {
		t.Fatalf("bound broadcast error = %v, want blame evidence", boundErr)
	}

	ackVerifier := tss.NewInMemoryAckVerifier(func(party tss.PartyID, digest [32]byte, signature []byte) error {
		if !ed25519.Verify(publicKeys[party], digest[:], signature) {
			return errors.New("invalid broadcast acknowledgment")
		}
		return nil
	})
	proofVerifier := identificationVerifierFunc(func(evidence tss.BlameEvidence, record tss.IdentificationRecord) error {
		if evidence.From != 2 || record.Accused != 2 || len(record.BroadcastCertificate) == 0 {
			return errors.New("broadcast identification context mismatch")
		}
		return nil
	})
	ctx := EvidenceContext{
		SessionID: sessionID, Parties: parties, Signers: parties,
		BroadcastACKVerifier: ackVerifier, IdentificationVerifier: proofVerifier,
	}
	if err := VerifyBlameEvidence(bound.Blame.Evidence, ctx); err != nil {
		t.Fatal(err)
	}
	ctx.BroadcastACKVerifier = nil
	if err := VerifyBlameEvidence(bound.Blame.Evidence, ctx); !errors.Is(err, tss.ErrMissingAckVerifier) {
		t.Fatalf("verification without ACK verifier = %v, want %v", err, tss.ErrMissingAckVerifier)
	}
}
