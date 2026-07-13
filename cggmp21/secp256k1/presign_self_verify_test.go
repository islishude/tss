//go:build integration

package secp256k1

import (
	"context"
	"crypto/sha256"
	"errors"
	"math/big"
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/wire"
)

func TestThresholdECDSA_PresignCryptographicSelfVerificationTamperMatrix(t *testing.T) {
	shares := secpKeygen(t, 2, 2)
	presigns := secpPresign(t, shares, tss.NewPartySet(1, 2))
	valid := presigns[1]
	if err := valid.VerifyCryptographicMaterialWithLimits(testLimits()); err != nil {
		t.Fatalf("valid presign self-verification failed: %v", err)
	}
	raw, err := valid.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	var restored Presign
	if err := restored.UnmarshalBinaryWithLimits(raw, testLimits()); err != nil {
		t.Fatal(err)
	}
	if err := restored.VerifyCryptographicMaterialWithLimits(testLimits()); err != nil {
		t.Fatalf("restored presign self-verification failed: %v", err)
	}
	replacementPoint := secp.ScalarBaseMult(secp.ScalarFromUint64(7))
	replacementPointBytes, err := secp.PointBytes(replacementPoint)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(*Presign) error
	}{
		{name: "gamma", mutate: func(p *Presign) error {
			p.state.Verification.Entries[0].Gamma = replacementPointBytes
			return nil
		}},
		{name: "enc k", mutate: func(p *Presign) error {
			p.state.Verification.Entries[0].EncK = []byte{1}
			return nil
		}},
		{name: "round1 K point", mutate: func(p *Presign) error {
			p.state.Verification.Entries[0].KPoint = replacementPointBytes
			return nil
		}},
		{name: "Paillier public key", mutate: func(p *Presign) error {
			p.state.Verification.Entries[0].PaillierPublicKey = p.state.Verification.Entries[1].PaillierPublicKey.Clone()
			return nil
		}},
		{name: "x bar point", mutate: func(p *Presign) error {
			p.state.Verification.Entries[0].XBarPoint = secp.Clone(replacementPoint)
			return nil
		}},
		{name: "delta share", mutate: func(p *Presign) error {
			delta := secp.ScalarFromUint64(7)
			p.state.Verification.Entries[0].Delta = &delta
			return nil
		}},
		{name: "K point", mutate: func(p *Presign) error {
			p.state.VerifyShares[0].KPoint = secp.Clone(replacementPoint)
			return nil
		}},
		{name: "chi point", mutate: func(p *Presign) error {
			p.state.VerifyShares[0].ChiPoint = secp.Clone(replacementPoint)
			return nil
		}},
		{name: "proof", mutate: func(p *Presign) error {
			p.state.VerifyShares[0].Proof.MPoint = replacementPointBytes
			return nil
		}},
		{name: "MTA contributions hash", mutate: func(p *Presign) error {
			p.state.VerifyShares[0].MTAContributionsHash[0] ^= 1
			return nil
		}},
		{name: "identification transcript binding", mutate: func(p *Presign) error {
			ciphertext := p.state.IdentificationTranscripts[1].Contributions[0].Outbound.Ciphertext
			ciphertext[len(ciphertext)-1] ^= 1
			return nil
		}},
		{name: "MTA base point", mutate: func(p *Presign) error {
			p.state.VerifyShares[0].MTABasePoint = replacementPointBytes
			return nil
		}},
		{name: "delta base point", mutate: func(p *Presign) error {
			p.state.VerifyShares[0].DeltaBasePoint = replacementPointBytes
			return nil
		}},
		{name: "child verification key", mutate: func(p *Presign) error {
			p.state.Derivation.ChildPublicKey = replacementPointBytes
			return nil
		}},
		{name: "transcript hash", mutate: func(p *Presign) error {
			p.state.TranscriptHash[0] ^= 1
			return nil
		}},
		{name: "local k share", mutate: func(p *Presign) error {
			return replacePresignSecretForTest(&p.state.KShare, secp.ScalarFromUint64(7))
		}},
		{name: "local chi share", mutate: func(p *Presign) error {
			return replacePresignSecretForTest(&p.state.ChiShare, secp.ScalarFromUint64(7))
		}},
		{name: "aggregate delta", mutate: func(p *Presign) error {
			return replacePresignSecretForTest(&p.state.DeltaAggregate, secp.ScalarFromUint64(7))
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tampered := clonePresignForTest(valid)
			if err := tc.mutate(tampered); err != nil {
				t.Fatal(err)
			}
			if err := tampered.VerifyCryptographicMaterialWithLimits(testLimits()); err == nil {
				t.Fatal("tampered presign passed cryptographic self-verification")
			}
		})
	}
}

func TestThresholdECDSA_StartSignRejectsTamperedPresignWithoutConsumption(t *testing.T) {
	shares := secpKeygen(t, 2, 2)
	presigns := secpPresign(t, shares, tss.NewPartySet(1, 2))
	tampered := clonePresignForTest(presigns[1])
	tampered.state.Verification.Entries[0].XBarPoint =
		secp.ScalarBaseMult(secp.ScalarFromUint64(7))
	digest := sha256.Sum256([]byte("tampered presign must not be consumed"))
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := StartSignDigestWithStore(shares[1], tampered, sessionID, digest[:], newTestSignAttemptStore()); err == nil {
		t.Fatal("StartSign accepted a tampered presign")
	}
	if IsPresignConsumed(tampered) {
		t.Fatal("StartSign consumed a presign that failed self-verification")
	}
}

func TestThresholdECDSA_StartSignRejectsInvalidSigmaWitnessesBeforeCommit(t *testing.T) {
	shares := secpKeygen(t, 2, 2)
	presigns := secpPresign(t, shares, tss.NewPartySet(1, 2))
	valid := presigns[1]

	tests := []struct {
		name   string
		mutate func(*Presign) error
	}{
		{name: "missing", mutate: func(p *Presign) error {
			destroyPresignSigmaOpeningRecords(p.state.SigmaOpeningRecords)
			p.state.SigmaOpeningRecords = nil
			return nil
		}},
		{name: "response binding", mutate: func(p *Presign) error {
			ciphertext := p.state.SigmaOpeningRecords[0].Response.Ciphertext
			ciphertext[len(ciphertext)-1] ^= 1
			return nil
		}},
		{name: "coordinated response and transcript mutation", mutate: func(p *Presign) error {
			recordCiphertext := p.state.SigmaOpeningRecords[0].Response.Ciphertext
			recordCiphertext[len(recordCiphertext)-1] ^= 1
			contributionCiphertext := p.state.IdentificationTranscripts[0].Contributions[0].Outbound.Ciphertext
			contributionCiphertext[len(contributionCiphertext)-1] ^= 1
			return nil
		}},
		{name: "opening relation", mutate: func(p *Presign) error {
			return rewriteSigmaOpeningXForTest(p)
		}},
		{name: "opening alternate representative", mutate: rewriteSigmaOpeningYEquivalentForTest},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tampered := clonePresignForTest(valid)
			if err := tc.mutate(tampered); err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256([]byte("invalid sigma witness " + tc.name))
			sessionID, err := tss.NewSessionID(nil)
			if err != nil {
				t.Fatal(err)
			}
			store := newTestSignAttemptStore()
			if _, _, err := StartSignDigestWithStore(shares[1], tampered, sessionID, digest[:], store); err == nil {
				t.Fatal("StartSign accepted invalid sigma identification witnesses")
			}
			if IsPresignConsumed(tampered) {
				t.Fatal("StartSign consumed a presign with invalid sigma identification witnesses")
			}
			store.mu.Lock()
			attempts := len(store.attempts)
			store.mu.Unlock()
			if attempts != 0 {
				t.Fatalf("StartSign committed %d durable attempts before sigma witness validation", attempts)
			}
		})
	}
}

func TestThresholdECDSA_ResumeSignRejectsTamperedPresignBeforeStoreLoad(t *testing.T) {
	shares := secpKeygen(t, 2, 2)
	presigns := secpPresign(t, shares, tss.NewPartySet(1, 2))
	store := &loadCountingSignAttemptStore{inner: newTestSignAttemptStore()}
	digest := sha256.Sum256([]byte("resume must verify presign before store load"))
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	session, _, err := StartSignDigestWithStore(shares[1], presigns[1], sessionID, digest[:], store)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*Presign) error
	}{
		{name: "public verification context", mutate: func(p *Presign) error {
			p.state.Verification.Entries[0].XBarPoint = secp.ScalarBaseMult(secp.ScalarFromUint64(7))
			return nil
		}},
		{name: "coordinated sigma response and transcript", mutate: func(p *Presign) error {
			recordCiphertext := p.state.SigmaOpeningRecords[0].Response.Ciphertext
			recordCiphertext[len(recordCiphertext)-1] ^= 1
			contributionCiphertext := p.state.IdentificationTranscripts[0].Contributions[0].Outbound.Ciphertext
			contributionCiphertext[len(contributionCiphertext)-1] ^= 1
			return nil
		}},
		{name: "sigma opening relation", mutate: rewriteSigmaOpeningXForTest},
		{name: "sigma opening alternate representative", mutate: rewriteSigmaOpeningYEquivalentForTest},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tampered := clonePresignForTest(presigns[1])
			if err := tc.mutate(tampered); err != nil {
				t.Fatal(err)
			}
			if _, _, err := ResumeSignWithLimits(
				context.Background(),
				shares[1],
				tampered,
				store,
				session.Guard(),
				testLimits(),
			); err == nil {
				t.Fatal("ResumeSign accepted a tampered presign")
			}
			if store.loadCount() != 0 {
				t.Fatal("ResumeSign loaded durable state before presign self-verification")
			}
		})
	}
}

func rewriteSigmaOpeningXForTest(p *Presign) error {
	var opening minimalResponseOpeningWire
	fieldLimits := wire.FieldLimits{"paillier_signed": tss.DefaultMaxPaillierCiphertextBytes}
	if err := wire.Unmarshal(
		p.state.SigmaOpeningRecords[0].Opening,
		&opening,
		wire.WithFieldLimits(fieldLimits),
	); err != nil {
		return err
	}
	defer clearMinimalResponseOpeningWireForTest(&opening)
	x, err := secp.ScalarFromBytes(opening.X)
	if err != nil {
		return err
	}
	replacement := secp.ScalarAdd(x, secp.ScalarOne())
	if replacement.IsZero() {
		replacement = secp.ScalarOne()
	}
	clear(opening.X)
	opening.X = replacement.Bytes()
	encoded, err := wire.Marshal(opening, wire.WithFieldLimitsForMarshal(fieldLimits))
	if err != nil {
		return err
	}
	clear(p.state.SigmaOpeningRecords[0].Opening)
	p.state.SigmaOpeningRecords[0].Opening = encoded
	return nil
}

func rewriteSigmaOpeningYEquivalentForTest(p *Presign) error {
	var opening minimalResponseOpeningWire
	fieldLimits := wire.FieldLimits{"paillier_signed": tss.DefaultMaxPaillierCiphertextBytes}
	if err := wire.Unmarshal(
		p.state.SigmaOpeningRecords[0].Opening,
		&opening,
		wire.WithFieldLimits(fieldLimits),
	); err != nil {
		return err
	}
	defer clearMinimalResponseOpeningWireForTest(&opening)
	y := new(big.Int).SetBytes(opening.Y)
	defer secret.ClearBigInt(y)
	if opening.YSign[0] == 1 {
		y.Neg(y)
	}
	peerEntry, ok := presignVerificationEntryFor(p, p.state.SigmaOpeningRecords[0].Peer)
	if !ok {
		return errors.New("missing peer verification entry")
	}
	localEntry, ok := presignVerificationEntryFor(p, p.state.Party)
	if !ok {
		return errors.New("missing local verification entry")
	}
	period := new(big.Int).Mul(secp.Order(), peerEntry.PaillierPublicKey.N)
	defer secret.ClearBigInt(period)
	period.Mul(period, localEntry.PaillierPublicKey.N)
	y.Add(y, period)
	clear(opening.Y)
	clear(opening.YSign)
	opening.YSign = []byte{0}
	opening.Y = y.Bytes()
	encoded, err := wire.Marshal(opening, wire.WithFieldLimitsForMarshal(fieldLimits))
	if err != nil {
		return err
	}
	clear(p.state.SigmaOpeningRecords[0].Opening)
	p.state.SigmaOpeningRecords[0].Opening = encoded
	return nil
}

func clearMinimalResponseOpeningWireForTest(opening *minimalResponseOpeningWire) {
	if opening == nil {
		return
	}
	clear(opening.X)
	clear(opening.YSign)
	clear(opening.Y)
	clear(opening.Rho)
	clear(opening.RhoY)
	*opening = minimalResponseOpeningWire{}
}

func replacePresignSecretForTest(dst **secret.Scalar, value secp.Scalar) error {
	replacement, err := secpSecretScalarFromScalar(value)
	if err != nil {
		return err
	}
	if *dst != nil {
		(*dst).Destroy()
	}
	*dst = replacement
	return nil
}
