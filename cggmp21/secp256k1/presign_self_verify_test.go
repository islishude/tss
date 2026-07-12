//go:build integration

package secp256k1

import (
	"context"
	"crypto/sha256"
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/secret"
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
	tampered := clonePresignForTest(presigns[1])
	tampered.state.Verification.Entries[0].XBarPoint =
		secp.ScalarBaseMult(secp.ScalarFromUint64(7))
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
