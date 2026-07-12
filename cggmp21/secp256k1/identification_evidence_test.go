package secp256k1

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
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

type identificationVerifierFunc func(tss.BlameEvidence, tss.IdentificationRecord) error

func (f identificationVerifierFunc) VerifyIdentificationFailure(evidence tss.BlameEvidence, record tss.IdentificationRecord) error {
	return f(evidence, record)
}

func TestVerifyBlameEvidenceRejectsBareIdentificationRecord(t *testing.T) {
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
	recordField, err := identificationProofEvidenceField(env, "sign-identification-invalid-proof", []byte("portable statement"), protocolAlert, keygenHash, presignHash)
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
	ctx := EvidenceContext{
		SessionID: sessionID, Parties: parties, Signers: parties,
		KeygenTranscriptHash: keygenHash, PresignTranscriptHash: presignHash,
		IdentificationVerifier: identificationVerifierFunc(func(tss.BlameEvidence, tss.IdentificationRecord) error { return nil }),
	}
	if err := VerifyBlameEvidence(encoded, ctx); err == nil {
		t.Fatal("bare identification record verified")
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
		Round: signStartRound, From: 2, PayloadType: payloadSignPartial,
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

	protocolErr := verificationErrorWithEvidence(env, tss.EvidenceKindSignPartial, "invalid certified sign partial", parties, errors.New("invalid partial"),
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

func TestPortableSignEvidenceFitsProductionSixteenSignerBudget(t *testing.T) {
	t.Parallel()
	parties := make(tss.PartySet, maxCGGMPSigners)
	for i := range parties {
		parties[i] = tss.PartyID(i + 1)
	}
	var sessionID, presignSessionID tss.SessionID
	sessionID[len(sessionID)-1] = 1
	presignSessionID[len(presignSessionID)-1] = 2

	// A structurally valid composite close to the production 3072-bit profile.
	// Its obvious factor keeps this Tier-0 size test deterministic and fast.
	q := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 3068), big.NewInt(1))
	n := new(big.Int).Mul(big.NewInt(5), q)
	pk := &pai.PublicKey{N: n, G: new(big.Int).Add(n, big.NewInt(1)), NSquared: new(big.Int).Mul(new(big.Int).Set(n), n)}
	rp := &zkpai.RingPedersenParams{N: new(big.Int).Set(n), S: big.NewInt(4), T: big.NewInt(4)}
	point := secp.ScalarBaseMult(secp.ScalarOne())
	pointBytes, err := secp.PointBytes(point)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := bytes.Repeat([]byte{0xa5}, 768) // N^2 at the 3072-bit profile.
	hash32 := func(value byte) []byte { return bytes.Repeat([]byte{value}, sha256.Size) }

	statement := &portableIdentificationStatement{
		Kind: portableIdentificationSign, SessionID: sessionID, Threshold: maxCGGMPThreshold,
		EnvelopeDigest: hash32(8),
		Parties:        parties.Clone(), Signers: parties.Clone(), PlanHash: hash32(1), SecurityParams: testSecurityParams(),
		PublicKey: pointBytes, KeygenTranscriptHash: hash32(2), AlertDigest: hash32(3), ContextHash: hash32(4),
		PresignSessionID: presignSessionID, PresignTranscriptHash: hash32(5), LittleR: secp.ScalarOne().Bytes(), Digest: hash32(6),
		Verification:   &presignVerificationContext{SessionID: presignSessionID, Round1Echo: hash32(7)},
		Identification: &portableSignIdentificationTranscript{Party: parties[0]},
	}
	for _, party := range parties {
		delta := secp.ScalarOne()
		statement.KeyParties = append(statement.KeyParties, portableIdentificationKeyParty{Party: party, VerificationShare: pointBytes, PaillierPublicKey: pk.Clone(), RingPedersenParams: rp.Clone()})
		statement.Verification.Entries = append(statement.Verification.Entries, presignVerificationEntry{Party: party, Gamma: pointBytes, EncK: bytes.Clone(ciphertext), PaillierPublicKey: pk.Clone(), XBarPoint: secp.Clone(point), Delta: &delta, KPoint: pointBytes, EncGamma: bytes.Clone(ciphertext)})
		statement.IdentificationHashes = append(statement.IdentificationHashes, portableSignIdentificationHash{Party: party, Hash: hash32(byte(party))})
		partial, envelopeErr := tss.NewEnvelope(tss.EnvelopeInput{Protocol: tss.ProtocolCGGMP21Secp256k1, SessionID: sessionID, Round: signStartRound, From: party, PayloadType: payloadSignPartial, Payload: bytes.Repeat([]byte{byte(party)}, 256)})
		if envelopeErr != nil {
			t.Fatal(envelopeErr)
		}
		partialBytes, marshalErr := partial.MarshalBinary()
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		statement.Partials = append(statement.Partials, portableIdentificationPartial{Party: party, Scalar: secp.ScalarOne().Bytes(), Envelope: partialBytes})
		if party != statement.Identification.Party {
			statement.Identification.Contributions = append(statement.Identification.Contributions, portableSignMTAContribution{Peer: party, InboundCiphertext: bytes.Clone(ciphertext), OutboundCiphertext: bytes.Clone(ciphertext)})
		}
	}
	identificationHash, err := portableSignIdentificationTranscriptHash(statement.Identification)
	if err != nil {
		t.Fatal(err)
	}
	statement.IdentificationHashes[0].Hash = identificationHash
	statementBytes, err := statement.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(statementBytes) > tss.DefaultMaxZKProofBytes {
		t.Fatalf("portable statement size %d exceeds %d", len(statementBytes), tss.DefaultMaxZKProofBytes)
	}

	accused, err := tss.NewEnvelope(tss.EnvelopeInput{Protocol: tss.ProtocolCGGMP21Secp256k1, SessionID: sessionID, Round: signIdentificationRound, From: parties[0], PayloadType: payloadSignIdentification, Payload: bytes.Repeat([]byte{0x5a}, maxIdentificationPayloadBytes)})
	if err != nil {
		t.Fatal(err)
	}
	accusedBytes, err := accused.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	record := &tss.IdentificationRecord{FailureClass: "sign-identification-invalid-proof", Accused: parties[0], SignedEnvelopeA: accusedBytes, BroadcastCertificate: bytes.Repeat([]byte{0x33}, maxCGGMPSigners*(tss.DefaultMaxEnvelopeSignatureBytes+128)), Statement: statementBytes}
	alert := record.ComputeAlertDigest()
	record.AlertDigest = alert[:]
	recordField, err := tss.IdentificationEvidenceField(record)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := tss.NewBlameEvidence(accused, tss.EvidenceKindSignIdentification, "invalid sign identification proof", []tss.EvidenceField{recordField})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := evidence.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > tss.DefaultMaxBlameEvidenceBytes {
		t.Fatalf("portable evidence size %d exceeds %d", len(encoded), tss.DefaultMaxBlameEvidenceBytes)
	}
}
