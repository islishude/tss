package secp256k1

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/wire"
)

func TestFast_SignAttemptRecordCanonicalRoundTrip(t *testing.T) {
	t.Parallel()
	record := testSignAttemptRecord(t, 1)
	raw1, err := record.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := record.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw1, raw2) {
		t.Fatal("sign attempt encoding is not deterministic")
	}
	decoded, err := tss.DecodeBinaryValue[SignAttemptRecord](raw1)
	if err != nil {
		t.Fatal(err)
	}
	if !record.Equal(decoded) {
		t.Fatal("sign attempt round trip changed the record")
	}
	if _, err := tss.DecodeBinaryValue[SignAttemptRecord](append(raw1, 0)); err == nil {
		t.Fatal("sign attempt accepted trailing data")
	}
}

func TestFast_SignAttemptRecordCodecAppliesCallerLimits(t *testing.T) {
	t.Parallel()

	record := testSignAttemptRecord(t, 1)
	limits := testLimits()
	raw, err := record.MarshalBinaryWithLimits(limits)
	if err != nil {
		t.Fatal(err)
	}
	smallFields := limits.fieldLimits()
	smallFields["envelope"] = len(record.CanonicalBaseEnvelopeBytes) - 1
	if _, err := record.MarshalWireMessage(wire.WithFieldLimitsForMarshal(smallFields)); err == nil {
		t.Fatal("sign attempt marshal ignored caller field limits")
	}
	var decoded SignAttemptRecord
	if err := decoded.UnmarshalWireMessage(
		raw,
		wire.WithFrameLimits(limits.frameLimits(len(raw)-1)),
		wire.WithFieldLimits(limits.fieldLimits()),
	); err == nil {
		t.Fatal("sign attempt unmarshal ignored caller frame limits")
	}
	if err := decoded.UnmarshalWireMessage(
		raw,
		wire.WithFrameLimits(limits.frameLimits(len(raw))),
		wire.WithFieldLimits(smallFields),
	); err == nil {
		t.Fatal("sign attempt unmarshal ignored caller field limits")
	}
	missing := limits.fieldLimits()
	delete(missing, "envelope")
	if _, err := record.MarshalWireMessage(wire.WithFieldLimitsForMarshal(missing)); err == nil {
		t.Fatal("sign attempt marshal accepted missing field limit")
	}
}

func TestFast_SignAttemptRecordRejectsNonCanonicalFieldSet(t *testing.T) {
	t.Parallel()

	record := testSignAttemptRecord(t, 1)
	raw, err := record.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	version, fields, err := wire.UnmarshalFields(raw, signAttemptWireType)
	if err != nil {
		t.Fatal(err)
	}
	missing, err := wire.MarshalFields(version, signAttemptWireType, fields[:len(fields)-1])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tss.DecodeBinaryValueWithLimits[SignAttemptRecord](missing, testLimits()); err == nil {
		t.Fatal("sign attempt accepted missing field")
	}
	fields[len(fields)-1].Tag = 29
	unknown, err := wire.MarshalFields(version, signAttemptWireType, fields)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tss.DecodeBinaryValueWithLimits[SignAttemptRecord](unknown, testLimits()); err == nil {
		t.Fatal("sign attempt accepted unknown field")
	}
}

func TestFast_SignAttemptRecordRejectsTampering(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*SignAttemptRecord)
	}{
		{"protocol_version", func(r *SignAttemptRecord) { r.ProtocolVersion++ }},
		{"presign", func(r *SignAttemptRecord) { r.PresignID[0] ^= 1 }},
		{"session", func(r *SignAttemptRecord) { r.SessionID[0] ^= 1 }},
		{"digest", func(r *SignAttemptRecord) { r.Digest[0] ^= 1 }},
		{"digest_binding", func(r *SignAttemptRecord) { r.DigestBindingHash[0] ^= 1 }},
		{"envelope", func(r *SignAttemptRecord) { r.CanonicalBaseEnvelopeBytes[len(r.CanonicalBaseEnvelopeBytes)-1] ^= 1 }},
		{"envelope_hash", func(r *SignAttemptRecord) { r.CanonicalBaseEnvelopeHash[0] ^= 1 }},
		{"envelope_digest", func(r *SignAttemptRecord) { r.EnvelopeDigest[0] ^= 1 }},
		{"payload_hash", func(r *SignAttemptRecord) { r.PayloadHash[0] ^= 1 }},
		{"intent", func(r *SignAttemptRecord) { r.IntentHash[0] ^= 1 }},
		{"attempt", func(r *SignAttemptRecord) { r.AttemptHash[0] ^= 1 }},
		{"policy_recipient", func(r *SignAttemptRecord) { r.DeliveryPolicy.Recipients = append(r.DeliveryPolicy.Recipients, 3) }},
		{"incomplete_signature", func(r *SignAttemptRecord) { r.SignatureR = bytes.Repeat([]byte{1}, 32) }},
		{"completed_high_s", func(r *SignAttemptRecord) {
			r.Completed = true
			r.SignatureR = secp.ScalarFromUint64(1).Bytes()
			r.SignatureS = secp.ScalarNeg(secp.ScalarFromUint64(1)).Bytes()
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			record := testSignAttemptRecord(t, 1)
			tc.mutate(&record)
			if _, err := record.MarshalBinary(); err == nil {
				t.Fatal("tampered sign attempt encoded")
			}
		})
	}
}

func TestFast_SignAttemptRecordRejectsRetiredEnvelopeLayoutOnRestore(t *testing.T) {
	t.Parallel()
	record := testSignAttemptRecord(t, 1)
	envWireType := (tss.Envelope{}).WireType()
	envVersion, fields, err := wire.UnmarshalFields(record.CanonicalBaseEnvelopeBytes, envWireType)
	if err != nil {
		t.Fatal(err)
	}
	retiredEnvelope, err := wire.MarshalFields(envVersion, envWireType, []wire.Field{
		{Tag: 1, Value: fields[0].Value},
		{Tag: 2, Value: wire.Uint16(envVersion)},
		{Tag: 3, Value: fields[1].Value},
		{Tag: 4, Value: fields[2].Value},
		{Tag: 5, Value: fields[3].Value},
		{Tag: 6, Value: fields[4].Value},
		{Tag: 7, Value: fields[5].Value},
		{Tag: 8, Value: fields[6].Value},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := record.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	attemptVersion, attemptFields, err := wire.UnmarshalFields(raw, signAttemptWireType)
	if err != nil {
		t.Fatal(err)
	}
	attemptFields[13].Value = retiredEnvelope
	raw, err = wire.MarshalFields(attemptVersion, signAttemptWireType, attemptFields)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tss.DecodeBinaryValueWithLimits[SignAttemptRecord](raw, testLimits()); err == nil {
		t.Fatal("restored sign attempt accepted retired embedded envelope layout")
	}
}

func TestFast_SignAttemptRecordRejectsRetiredLowSLayout(t *testing.T) {
	t.Parallel()

	record := testSignAttemptRecord(t, 1)
	raw, err := record.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	version, fields, err := wire.UnmarshalFields(raw, signAttemptWireType)
	if err != nil {
		t.Fatal(err)
	}
	retired := make([]wire.Field, 0, len(fields)+1)
	for _, field := range fields {
		if field.Tag <= 13 {
			retired = append(retired, field)
			continue
		}
		if field.Tag == 14 {
			retired = append(retired, wire.Field{Tag: 14, Value: wire.Bool(true)})
		}
		retired = append(retired, wire.Field{Tag: field.Tag + 1, Value: field.Value})
	}
	retiredRaw, err := wire.MarshalFields(version, signAttemptWireType, retired)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tss.DecodeBinaryValue[SignAttemptRecord](retiredRaw); err == nil {
		t.Fatal("sign attempt accepted retired layout with configurable LowS")
	}
}

func TestFast_SignAttemptRecordRejectsJSONDecoding(t *testing.T) {
	t.Parallel()
	var record SignAttemptRecord
	if err := json.Unmarshal([]byte(`{"Protocol":"cggmp21-secp256k1"}`), &record); err == nil {
		t.Fatal("sign attempt accepted direct JSON decoding")
	}
}

func TestFast_FileSignAttemptStoreIdempotentAndConflictingCommits(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newFastFileSignAttemptStore(t)
	record := testSignAttemptRecord(t, 1)

	first, err := store.CommitSignAttempt(ctx, record)
	if err != nil {
		t.Fatal(err)
	}
	if first.Status != SignAttemptCreated {
		t.Fatalf("first status = %d, want created", first.Status)
	}
	second, err := store.CommitSignAttempt(ctx, record)
	if err != nil {
		t.Fatal(err)
	}
	if second.Status != SignAttemptExistingSame {
		t.Fatalf("second status = %d, want existing", second.Status)
	}
	if !bytes.Equal(first.Record.CanonicalBaseEnvelopeBytes, second.Record.CanonicalBaseEnvelopeBytes) {
		t.Fatal("idempotent commit changed the durable envelope")
	}
	conflict := testSignAttemptRecord(t, 2)
	conflict.PresignID = bytes.Clone(record.PresignID)
	conflict.IntentHash = signAttemptIntentHash(conflict)
	conflict.AttemptHash = signAttemptHash(conflict)
	if _, err := store.CommitSignAttempt(ctx, conflict); !errors.Is(err, ErrSignAttemptConflict) {
		t.Fatalf("conflicting commit error = %v", err)
	}
	nondeterministic := sameIntentDifferentAttemptRecord(t, record)
	if _, err := store.CommitSignAttempt(ctx, nondeterministic); !errors.Is(err, ErrSignAttemptNonDeterminism) {
		t.Fatalf("non-deterministic commit error = %v", err)
	}

	claimBytes, err := os.ReadFile(store.claimPath(record.PresignID))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(claimBytes, record.CanonicalBaseEnvelopeBytes) {
		t.Fatal("file store persisted the confidential envelope in plaintext")
	}
}

func TestFast_FileSignAttemptStoreRejectsCommitAfterDestroy(t *testing.T) {
	t.Parallel()
	store := newFastFileSignAttemptStore(t)
	record := testSignAttemptRecord(t, 1)
	store.Destroy()
	if _, err := store.CommitSignAttempt(context.Background(), record); err == nil {
		t.Fatal("destroyed file store accepted a commit")
	}
}

func TestFast_FileSignAttemptStoreRejectsCompletedCommitCandidate(t *testing.T) {
	t.Parallel()
	store := newFastFileSignAttemptStore(t)
	record := testSignAttemptRecord(t, 1)
	record.Completed = true
	record.SignatureR = bytes.Repeat([]byte{1}, 32)
	record.SignatureS = bytes.Repeat([]byte{2}, 32)
	if _, err := store.CommitSignAttempt(context.Background(), record); err == nil {
		t.Fatal("file store accepted a completed commit candidate")
	}
}

func TestFast_FileSignAttemptStoreConcurrentCommitLinearizes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newFastFileSignAttemptStore(t)
	record := testSignAttemptRecord(t, 1)
	const workers = 16
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	envelopes := make(chan []byte, workers)
	for range workers {
		wg.Go(func() {
			committed, err := store.CommitSignAttempt(ctx, record)
			errs <- err
			if err == nil {
				envelopes <- committed.Record.CanonicalBaseEnvelopeBytes
			}
		})
	}
	wg.Wait()
	close(errs)
	close(envelopes)
	for err := range errs {
		if err != nil {
			t.Fatalf("identical concurrent commit: %v", err)
		}
	}
	for envelope := range envelopes {
		if !bytes.Equal(envelope, record.CanonicalBaseEnvelopeBytes) {
			t.Fatal("concurrent commit returned a different envelope")
		}
	}
}

func TestFast_FileSignAttemptStoreCompletionIsIdempotent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newFastFileSignAttemptStore(t)
	record := testSignAttemptRecord(t, 1)
	if _, err := store.CommitSignAttempt(ctx, record); err != nil {
		t.Fatal(err)
	}
	result := SignAttemptResult{
		PresignID:   bytes.Clone(record.PresignID),
		AttemptHash: bytes.Clone(record.AttemptHash),
		Signature: Signature{
			R:          bytes.Repeat([]byte{1}, 32),
			S:          bytes.Repeat([]byte{2}, 32),
			RecoveryID: 3,
		},
	}
	completed, err := store.CompleteSignAttempt(ctx, result)
	if err != nil {
		t.Fatal(err)
	}
	if completed.SignatureRecoveryID != 3 {
		t.Fatalf("expected RecoveryID 3, got %d", completed.SignatureRecoveryID)
	}
	repeated, err := store.CompleteSignAttempt(ctx, result)
	if err != nil {
		t.Fatal(err)
	}
	if repeated.SignatureRecoveryID != 3 {
		t.Fatalf("expected RecoveryID 3 on repeat, got %d", repeated.SignatureRecoveryID)
	}
	if !completed.Completed || !bytes.Equal(completed.SignatureR, repeated.SignatureR) {
		t.Fatal("completion was not idempotent")
	}
	loaded, err := store.LoadSignAttempt(ctx, record.PresignID)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Completed || !bytes.Equal(loaded.SignatureS, result.Signature.S) {
		t.Fatal("completed record was not loaded")
	}
}

func TestFast_FileSignAttemptStoreTamperedCiphertextFailsClosed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newFastFileSignAttemptStore(t)
	record := testSignAttemptRecord(t, 1)
	if _, err := store.CommitSignAttempt(ctx, record); err != nil {
		t.Fatal(err)
	}
	path := store.claimPath(record.PresignID)
	raw, err := os.ReadFile(path) //nolint:gosec // test-owned temporary directory
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 1
	if err := os.WriteFile(path, raw, 0o600); err != nil { //nolint:gosec // test-owned temporary directory
		t.Fatal(err)
	}
	if _, err := store.LoadSignAttempt(ctx, record.PresignID); !errors.Is(err, ErrSignAttemptCorrupt) {
		t.Fatalf("tampered ciphertext error = %v", err)
	}
}

func TestFast_FileSignAttemptStoreOrphanObjectDoesNotClaimPresign(t *testing.T) {
	t.Parallel()
	store := newFastFileSignAttemptStore(t)
	record := testSignAttemptRecord(t, 1)
	objectPath, err := store.writeEncryptedObject(record, "base-attempt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(objectPath); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadSignAttempt(context.Background(), record.PresignID); !errors.Is(err, ErrSignAttemptNotFound) {
		t.Fatalf("orphan object created a claim: %v", err)
	}
	if _, err := store.CommitSignAttempt(context.Background(), record); err != nil {
		t.Fatal(err)
	}
}

func TestFast_FileSignAttemptStoreDeliveryProgressIsDurable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newFastFileSignAttemptStore(t)
	record := testSignAttemptRecord(t, 1)
	if _, err := store.CommitSignAttempt(ctx, record); err != nil {
		t.Fatal(err)
	}
	env, err := decodeSignAttemptEnvelope(record.CanonicalBaseEnvelopeBytes)
	if err != nil {
		t.Fatal(err)
	}
	ack1 := testBroadcastAck(env, 1)
	updated, err := store.UpdateSignAttemptDelivery(ctx, SignAttemptDeliveryUpdate{
		PresignID:   record.PresignID,
		AttemptHash: record.AttemptHash,
		Ack:         &ack1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.DeliveryState.Acks) != 1 || updated.DeliveryState.DeliveryComplete {
		t.Fatalf("unexpected partial delivery state: %#v", updated.DeliveryState)
	}
	if repeated, err := store.UpdateSignAttemptDelivery(ctx, SignAttemptDeliveryUpdate{
		PresignID:   record.PresignID,
		AttemptHash: record.AttemptHash,
		Ack:         &ack1,
	}); err != nil {
		t.Fatal(err)
	} else if len(repeated.DeliveryState.Acks) != 1 {
		t.Fatal("duplicate ack was not idempotent")
	}
	ack2 := testBroadcastAck(env, 2)
	cert, err := tss.NewBroadcastCertificate(env, record.DeliveryPolicy.Recipients, []tss.BroadcastAck{ack1, ack2})
	if err != nil {
		t.Fatal(err)
	}
	completed, err := store.UpdateSignAttemptDelivery(ctx, SignAttemptDeliveryUpdate{
		PresignID:   record.PresignID,
		AttemptHash: record.AttemptHash,
		Certificate: cert,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !completed.DeliveryState.DeliveryComplete || completed.DeliveryState.Certificate == nil ||
		len(completed.DeliveryState.Acks) != len(record.DeliveryPolicy.Recipients) {
		t.Fatalf("delivery certificate was not durable: %#v", completed.DeliveryState)
	}
	loaded, err := store.LoadSignAttempt(ctx, record.PresignID)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.DeliveryState.DeliveryComplete {
		t.Fatal("loaded attempt lost durable delivery completion")
	}
}

func TestFast_FileSignAttemptStoreBurnBlocksFutureAttempts(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newFastFileSignAttemptStore(t)
	record := testSignAttemptRecord(t, 1)
	if err := store.BurnPresign(ctx, SignAttemptBurn{PresignID: record.PresignID, Reason: "operator requested"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadSignAttempt(ctx, record.PresignID); !errors.Is(err, ErrSignAttemptBurned) {
		t.Fatalf("burned load error = %v", err)
	}
	if _, err := store.CommitSignAttempt(ctx, record); !errors.Is(err, ErrSignAttemptBurned) {
		t.Fatalf("commit after burn error = %v", err)
	}
	if err := store.BurnPresign(ctx, SignAttemptBurn{PresignID: record.PresignID, Reason: "repeat"}); err != nil {
		t.Fatalf("repeat burn should be idempotent: %v", err)
	}
}

func TestFast_FileSignAttemptStoreBurnAfterCommitConflicts(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newFastFileSignAttemptStore(t)
	record := testSignAttemptRecord(t, 1)
	if _, err := store.CommitSignAttempt(ctx, record); err != nil {
		t.Fatal(err)
	}
	if err := store.BurnPresign(ctx, SignAttemptBurn{PresignID: record.PresignID, Reason: "too late"}); !errors.Is(err, ErrSignAttemptConflict) {
		t.Fatalf("burn after commit error = %v", err)
	}
	loaded, err := store.LoadSignAttempt(ctx, record.PresignID)
	if err != nil {
		t.Fatal(err)
	}
	if !record.SameAttempt(loaded) {
		t.Fatal("burn after commit changed the existing attempt")
	}
}

func FuzzSignAttemptRecord(f *testing.F) {
	record := testSignAttemptRecord(f, 1)
	raw, err := record.MarshalBinary()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Fuzz(func(t *testing.T, in []byte) {
		decoded, err := tss.DecodeBinaryValue[SignAttemptRecord](in)
		if err != nil {
			return
		}
		canonical, err := decoded.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(in, canonical) {
			t.Fatal("accepted non-canonical sign attempt")
		}
	})
}

func testSignAttemptRecord(t testing.TB, marker byte) SignAttemptRecord {
	t.Helper()
	var sessionID tss.SessionID
	sessionID[0] = marker
	contextHash := bytes.Repeat([]byte{0x22}, sha256.Size)
	digest := bytes.Repeat([]byte{marker}, sha256.Size)
	digestBindingHash := digestHash(digest, contextHash)
	signPlanHash := bytes.Repeat([]byte{0x33}, sha256.Size)
	payload := signPartialPayload{
		S:                   testSecretScalar(t, 1),
		PresignTranscript:   bytes.Repeat([]byte{0x11}, sha256.Size),
		PresignContext:      contextHash,
		DigestHash:          digestBindingHash,
		PartialEquationHash: bytes.Repeat([]byte{0x44}, sha256.Size),
		PlanHash:            signPlanHash,
	}
	payloadBytes, err := marshalSignPartialPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	env, err := tss.NewEnvelope(tss.EnvelopeInput{
		Protocol:    tss.ProtocolCGGMP21Secp256k1,
		SessionID:   sessionID,
		Round:       1,
		From:        1,
		PayloadType: payloadSignPartial,
		Payload:     payloadBytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	envelopeBytes, err := env.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	envelopeHash := sha256.Sum256(envelopeBytes)
	payloadHash := tss.PayloadHashFromEnvelope(env)
	policy, err := CGGMP21Policies().Match(tss.ProtocolCGGMP21Secp256k1, env.Round, env.PayloadType)
	if err != nil {
		t.Fatal(err)
	}
	envelopeDigest := env.Digest()
	record := SignAttemptRecord{
		RecordVersion:              signAttemptRecordVersion,
		Protocol:                   tss.ProtocolCGGMP21Secp256k1,
		ProtocolVersion:            tss.ProtocolVersion,
		PresignID:                  bytes.Repeat([]byte{0x55}, sha256.Size),
		SessionID:                  sessionID,
		Party:                      1,
		SignerSetHash:              signAttemptSignerSetHash(tss.NewPartySet(1, 2)),
		SignPlanHash:               signPlanHash,
		ContextHash:                contextHash,
		Digest:                     digest,
		DigestBindingHash:          digestBindingHash,
		CanonicalBaseEnvelopeBytes: envelopeBytes,
		CanonicalBaseEnvelopeHash:  envelopeHash[:],
		EnvelopeDigest:             envelopeDigest[:],
		PayloadHash:                payloadHash[:],
		DeliveryPolicy: SignAttemptDeliveryPolicy{
			Mode:                 policy.Mode,
			Confidentiality:      policy.Confidentiality,
			BroadcastConsistency: policy.BroadcastConsistency,
			Recipients:           tss.NewPartySet(1, 2),
		},
	}
	record.IntentHash = signAttemptIntentHash(record)
	record.AttemptHash = signAttemptHash(record)
	if err := validateSignAttemptRecord(record); err != nil {
		t.Fatal(err)
	}
	return record
}

func sameIntentDifferentAttemptRecord(t testing.TB, record SignAttemptRecord) SignAttemptRecord {
	t.Helper()
	env, err := decodeSignAttemptEnvelope(record.CanonicalBaseEnvelopeBytes)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := unmarshalSignPartialPayload(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	payload.PartialEquationHash = bytes.Clone(payload.PartialEquationHash)
	payload.PartialEquationHash[0] ^= 1
	env.Payload, err = marshalSignPartialPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	envelopeBytes, err := env.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	envelopeHash := sha256.Sum256(envelopeBytes)
	payloadHash := tss.PayloadHashFromEnvelope(env)
	envelopeDigest := env.Digest()
	out := record.Clone()
	out.CanonicalBaseEnvelopeBytes = envelopeBytes
	out.CanonicalBaseEnvelopeHash = envelopeHash[:]
	out.EnvelopeDigest = envelopeDigest[:]
	out.PayloadHash = payloadHash[:]
	out.AttemptHash = signAttemptHash(out)
	if !bytes.Equal(out.IntentHash, record.IntentHash) {
		t.Fatal("helper changed intent hash")
	}
	if err := validateSignAttemptRecord(out); err != nil {
		t.Fatal(err)
	}
	return out
}

func testBroadcastAck(env tss.Envelope, party tss.PartyID) tss.BroadcastAck {
	ack := tss.BroadcastAck{Party: party, Signature: []byte{byte(party)}}
	ack.PayloadHash = tss.PayloadHashFromEnvelope(env)
	ack.EnvelopeDigest = env.Digest()
	return ack
}

func newFastFileSignAttemptStore(t testing.TB) *FileSignAttemptStore {
	t.Helper()
	store, err := NewFileSignAttemptStore(t.TempDir(), []byte("test-sign-attempt-passphrase"), &tss.PassphraseParams{
		Time:    1,
		Memory:  1024,
		Threads: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Destroy)
	return store
}
