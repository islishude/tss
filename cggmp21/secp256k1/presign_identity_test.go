package secp256k1

import (
	"bytes"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
)

func TestFast_PresignContentIDDeterministicAndConsumedIndependent(t *testing.T) {
	t.Parallel()
	presign := minimalCGGMP21Presign(t)
	first, err := presign.contentID()
	if err != nil {
		t.Fatal(err)
	}
	second, err := presign.contentID()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("presign content ID is not deterministic")
	}
	presign.state.Consumed.Store(true)
	consumed, err := presign.contentID()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, consumed) {
		t.Fatal("runtime consumed state changed presign content ID")
	}
}

func TestFast_PresignContentIDBindsPersistedState(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*Presign) error
	}{
		{name: "plan hash", mutate: func(p *Presign) error {
			p.state.PlanHash[0] ^= 1
			return nil
		}},
		{name: "verification gamma", mutate: func(p *Presign) error {
			point := secp.ScalarBaseMult(secp.ScalarFromUint64(2))
			encoded, err := secp.PointBytes(point)
			if err != nil {
				return err
			}
			p.state.Verification.Entries[0].Gamma = encoded
			return nil
		}},
		{name: "k share", mutate: func(p *Presign) error {
			value, err := secpSecretScalarFromScalar(secp.ScalarFromUint64(2))
			if err != nil {
				return err
			}
			p.state.KShare.Destroy()
			p.state.KShare = value
			return nil
		}},
		{name: "chi share", mutate: func(p *Presign) error {
			value, err := secpSecretScalarFromScalar(secp.ScalarFromUint64(2))
			if err != nil {
				return err
			}
			p.state.ChiShare.Destroy()
			p.state.ChiShare = value
			return nil
		}},
		{name: "aggregate delta", mutate: func(p *Presign) error {
			value, err := secpSecretScalarFromScalar(secp.ScalarFromUint64(2))
			if err != nil {
				return err
			}
			p.state.DeltaAggregate.Destroy()
			p.state.DeltaAggregate = value
			return nil
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			original := minimalCGGMP21Presign(t)
			want, err := original.contentID()
			if err != nil {
				t.Fatal(err)
			}
			mutated := clonePresignForTest(original)
			if err := tc.mutate(mutated); err != nil {
				t.Fatal(err)
			}
			got, err := mutated.contentID()
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(want, got) {
				t.Fatal("persisted presign mutation did not change content ID")
			}
		})
	}
}

func TestFast_PresignContentIDReturnsEncodingErrors(t *testing.T) {
	t.Parallel()
	presign := minimalCGGMP21Presign(t)
	presign.state.R = &secp.Point{}
	if _, err := presign.contentID(); err == nil {
		t.Fatal("content ID ignored invalid point encoding")
	}
}

func TestFast_PresignVerificationContextRejectsSignerSetMismatch(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*Presign)
	}{
		{name: "out of order", mutate: func(p *Presign) {
			p.state.Verification.Entries[0], p.state.Verification.Entries[1] =
				p.state.Verification.Entries[1], p.state.Verification.Entries[0]
		}},
		{name: "duplicate", mutate: func(p *Presign) {
			p.state.Verification.Entries[1].Party = p.state.Verification.Entries[0].Party
		}},
		{name: "missing", mutate: func(p *Presign) {
			p.state.Verification.Entries = p.state.Verification.Entries[:1]
		}},
		{name: "extra", mutate: func(p *Presign) {
			p.state.Verification.Entries = append(
				p.state.Verification.Entries,
				p.state.Verification.Entries[0].clone(),
			)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			presign := minimalCGGMP21Presign(t)
			tc.mutate(presign)
			if err := presign.ValidateWithLimits(testLimits()); err == nil {
				t.Fatal("invalid verification context was accepted")
			}
		})
	}
}

func TestFast_PresignRejectsChildVerificationKeyDetachedFromParent(t *testing.T) {
	t.Parallel()

	presign := minimalCGGMP21Presign(t)
	if err := presign.ValidateWithLimits(testLimits()); err != nil {
		t.Fatalf("valid presign fixture: %v", err)
	}
	child, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromUint64(2)))
	if err != nil {
		t.Fatal(err)
	}
	presign.state.Derivation.ChildPublicKey = child
	if err := presign.ValidateWithLimits(testLimits()); err == nil {
		t.Fatal("presign accepted child verification key detached from parent and shift")
	}
}
