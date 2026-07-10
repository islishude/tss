package paillier

import (
	"math/big"
	"testing"
)

func TestNewProofVerifiersRejectMalformedProofsWithoutPanic(t *testing.T) {
	t.Run("enc", func(t *testing.T) {
		params, stmt, _, proof := encProofFixture(t)
		state := []byte("enc matrix")
		for _, tc := range []struct {
			name   string
			proof  *EncProof
			mutate func(*EncProof)
		}{
			{name: "nil proof", proof: nil},
			{name: "nil z1", proof: proof.Clone(), mutate: func(p *EncProof) { p.Z1 = nil }},
			{name: "nil z3", proof: proof.Clone(), mutate: func(p *EncProof) { p.Z3 = nil }},
			{name: "empty transcript hash", proof: proof.Clone(), mutate: func(p *EncProof) { p.TranscriptHash = nil }},
		} {
			t.Run(tc.name, func(t *testing.T) {
				candidate := tc.proof
				if tc.mutate != nil {
					tc.mutate(candidate)
				}
				requireVerifyErrorNoPanic(t, func() error {
					return VerifyEnc(params, state, stmt, candidate)
				})
			})
		}
	})

	t.Run("affg", func(t *testing.T) {
		params, stmt, _, proof := affGProofFixture(t)
		state := []byte("affg matrix")
		for _, tc := range []struct {
			name   string
			proof  *AffGProof
			mutate func(*AffGProof)
		}{
			{name: "nil proof", proof: nil},
			{name: "nil z3", proof: proof.Clone(), mutate: func(p *AffGProof) { p.Z3 = nil }},
			{name: "nil z4", proof: proof.Clone(), mutate: func(p *AffGProof) { p.Z4 = nil }},
			{name: "empty transcript hash", proof: proof.Clone(), mutate: func(p *AffGProof) { p.TranscriptHash = nil }},
		} {
			t.Run(tc.name, func(t *testing.T) {
				candidate := tc.proof
				if tc.mutate != nil {
					tc.mutate(candidate)
				}
				requireVerifyErrorNoPanic(t, func() error {
					return VerifyAffG(params, state, stmt, candidate)
				})
			})
		}
	})

	t.Run("logstar", func(t *testing.T) {
		params, stmt, _, proof := logStarProofFixture(t)
		state := []byte("logstar matrix")
		for _, tc := range []struct {
			name   string
			proof  *LogStarProof
			mutate func(*LogStarProof)
		}{
			{name: "nil proof", proof: nil},
			{name: "nil z1", proof: proof.Clone(), mutate: func(p *LogStarProof) { p.Z1 = nil }},
			{name: "nil z3", proof: proof.Clone(), mutate: func(p *LogStarProof) { p.Z3 = nil }},
			{name: "nil Y", proof: proof.Clone(), mutate: func(p *LogStarProof) { p.Y = nil }},
			{name: "empty transcript hash", proof: proof.Clone(), mutate: func(p *LogStarProof) { p.TranscriptHash = nil }},
		} {
			t.Run(tc.name, func(t *testing.T) {
				candidate := tc.proof
				if tc.mutate != nil {
					tc.mutate(candidate)
				}
				requireVerifyErrorNoPanic(t, func() error {
					return VerifyLogStar(params, state, stmt, candidate)
				})
			})
		}
	})
}

func TestProofVerifiersRejectSmallRingPedersenAuxModulus(t *testing.T) {
	params, stmt, _, proof := encProofFixture(t)
	stmt.VerifierAux = &RingPedersenParams{
		N: big.NewInt(15),
		S: big.NewInt(2),
		T: big.NewInt(4),
	}
	if err := VerifyEnc(params, []byte("enc matrix"), stmt, proof); err == nil {
		t.Fatal("VerifyEnc accepted undersized Ring-Pedersen auxiliary modulus")
	}
	if err := params.CheckRingPedersenModulus(stmt.VerifierAux.N); err == nil {
		t.Fatal("CheckRingPedersenModulus accepted undersized modulus")
	}
}

func TestProofVerifiersRejectNilVerifierAuxWithoutPanic(t *testing.T) {
	t.Run("enc", func(t *testing.T) {
		params, stmt, _, proof := encProofFixture(t)
		stmt.VerifierAux = nil
		requireVerifyErrorNoPanic(t, func() error {
			return VerifyEnc(params, []byte("nil aux"), stmt, proof)
		})
	})
	t.Run("affg", func(t *testing.T) {
		params, stmt, _, proof := affGProofFixture(t)
		stmt.VerifierAux = nil
		requireVerifyErrorNoPanic(t, func() error {
			return VerifyAffG(params, []byte("nil aux"), stmt, proof)
		})
	})
	t.Run("logstar", func(t *testing.T) {
		params, stmt, _, proof := logStarProofFixture(t)
		stmt.VerifierAux = nil
		requireVerifyErrorNoPanic(t, func() error {
			return VerifyLogStar(params, []byte("nil aux"), stmt, proof)
		})
	})
}

func TestRingPedersenVerifierRejectsSecurityParamFloorMismatch(t *testing.T) {
	sk := testPaillierKey(t, 512)
	params, lambda, err := GenerateRingPedersenParams(nil, sk)
	if err != nil {
		t.Fatal(err)
	}
	defer lambda.Destroy()
	proof, err := ProveRingPedersen(nil, []byte("rp floor"), sk, params, lambda, 1)
	if err != nil {
		t.Fatal(err)
	}
	tooStrict := fastProofParams()
	tooStrict.MinPaillierBits = 768
	if VerifyRingPedersen(tooStrict, []byte("rp floor"), params, 1, proof) {
		t.Fatal("VerifyRingPedersen accepted modulus below SecurityParams floor")
	}
}

func requireVerifyErrorNoPanic(t *testing.T, verify func() error) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("verifier panicked: %v", recovered)
		}
	}()
	if err := verify(); err == nil {
		t.Fatal("verifier accepted malformed proof")
	}
}
