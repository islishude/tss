package secp256k1

import (
	"bytes"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
)

func TestFastPresignContentIDDeterministicAndLifecycleIndependent(t *testing.T) {
	p := minimalCGGMP21Presign(t)
	defer p.Destroy()
	first, err := p.contentIDWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	second, err := p.contentIDWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("presign content ID is not deterministic")
	}
	p.state.Consumed.Store(true)
	third, err := p.contentIDWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, third) {
		t.Fatal("mutable consumed state changed content ID")
	}
}

func TestFastPresignContentIDBindsNormalizedFigure8State(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Presign)
	}{
		{name: "presign id", mutate: func(p *Presign) { p.state.PresignID[0] ^= 1 }},
		{name: "epoch id", mutate: func(p *Presign) { p.state.EpochID[0] ^= 1 }},
		{name: "gamma", mutate: func(p *Presign) { p.state.Gamma = secp.ScalarBaseMult(secp.ScalarFromUint64(2)) }},
		{name: "k share", mutate: func(p *Presign) {
			p.state.KShare.Destroy()
			p.state.KShare = testSecretScalar(t, 2)
		}},
		{name: "chi share", mutate: func(p *Presign) {
			p.state.ChiShare.Destroy()
			p.state.ChiShare = testSecretScalar(t, 2)
		}},
		{name: "commitment", mutate: func(p *Presign) { p.state.Commitments[0].DeltaTilde[1] ^= 1 }},
		{name: "transcript", mutate: func(p *Presign) { p.state.TranscriptHash[0] ^= 1 }},
		{name: "plan", mutate: func(p *Presign) { p.state.PlanHash[0] ^= 1 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			base := minimalCGGMP21Presign(t)
			defer base.Destroy()
			before, err := base.contentIDWithLimits(testLimits())
			if err != nil {
				t.Fatal(err)
			}
			mutated := minimalCGGMP21Presign(t)
			defer mutated.Destroy()
			tc.mutate(mutated)
			after, err := mutated.contentIDWithLimits(testLimits())
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(before, after) {
				t.Fatal("content ID did not bind mutation")
			}
		})
	}
}

func TestFastPresignContentIDRejectsDestroyedTuple(t *testing.T) {
	p := minimalCGGMP21Presign(t)
	p.state.KShare.Destroy()
	if _, err := p.contentIDWithLimits(testLimits()); err == nil {
		t.Fatal("destroyed normalized tuple encoded into a content ID")
	}
	p.Destroy()
}
