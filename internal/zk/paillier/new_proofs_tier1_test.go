//go:build tier1

package paillier

import (
	"math/big"
	"testing"
)

func TestEncProofVerificationMatrix(t *testing.T) {
	t.Parallel()
	params, stmt, witness, proof := encProofFixture(t)
	state := []byte("enc matrix")
	if err := VerifyEnc(params, state, stmt, proof); err != nil {
		t.Fatal(err)
	}
	if err := VerifyEnc(params, []byte("other state"), stmt, proof); err == nil {
		t.Fatal("EncProof verified under wrong transcript state")
	}

	wrongKey := testPaillierKey(t, 1024)
	wrongStmt := stmt
	wrongStmt.ProverPaillierN = wrongKey.PublicKey
	if err := VerifyEnc(params, state, wrongStmt, proof); err == nil {
		t.Fatal("EncProof verified under wrong Paillier key")
	}

	// A VerifierAux with a prime modulus must be rejected — Ring-Pedersen
	// commitments require a composite modulus with unknown factorisation.
	primeStmt := stmt
	primeStmt.VerifierAux = primeRingPedersenFixture()
	if err := VerifyEnc(params, state, primeStmt, proof); err == nil {
		t.Fatal("EncProof verified with prime VerifierAux modulus")
	}

	for _, tc := range []struct {
		name   string
		mutate func(*EncProof)
	}{
		{name: "transcript", mutate: func(p *EncProof) { p.TranscriptHash[0] ^= 1 }},
		{name: "S non unit", mutate: func(p *EncProof) { p.S = new(big.Int).Set(stmt.VerifierAux.N) }},
		{name: "A invalid ciphertext", mutate: func(p *EncProof) { p.A = new(big.Int).Set(stmt.ProverPaillierN.NSquared) }},
		{name: "C non unit", mutate: func(p *EncProof) { p.C = new(big.Int).Set(stmt.VerifierAux.N) }},
		{name: "z1 out of range", mutate: func(p *EncProof) { p.Z1 = signedPowerOfTwo(params.EncRange() + 2) }},
		{name: "z2 non unit", mutate: func(p *EncProof) { p.Z2 = new(big.Int).Set(stmt.ProverPaillierN.N) }},
		{name: "z3 out of range", mutate: func(p *EncProof) { p.Z3 = multRangeOutside(stmt.VerifierAux.N, params.EncRange()+2) }},
		{name: "Paillier equation", mutate: func(p *EncProof) { p.A = new(big.Int).Add(p.A, big.NewInt(1)) }},
		{name: "Ring-Pedersen equation", mutate: func(p *EncProof) { p.S = new(big.Int).Add(p.S, big.NewInt(1)) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tampered := proof.Clone()
			tc.mutate(tampered)
			if err := VerifyEnc(params, state, stmt, tampered); err == nil {
				t.Fatal("tampered EncProof verified")
			}
		})
	}

	badWitness := witness
	badWitness.K = testSecpSecretScalar(t, big.NewInt(18))
	if _, err := ProveEnc(params, state, stmt, badWitness, nil); err == nil {
		t.Fatal("EncProof accepted witness that does not open ciphertext")
	}
}

func TestAffGProofVerificationMatrix(t *testing.T) {
	t.Parallel()
	params, stmt, witness, proof := affGProofFixture(t)
	state := []byte("affg matrix")
	if err := VerifyAffG(params, state, stmt, proof); err != nil {
		t.Fatal(err)
	}
	if err := VerifyAffG(params, []byte("other state"), stmt, proof); err == nil {
		t.Fatal("AffGProof verified under wrong transcript state")
	}

	wrongKey := testPaillierKey(t, 1024)
	wrongStmt := stmt
	wrongStmt.ProverPaillierN = wrongKey.PublicKey
	if err := VerifyAffG(params, state, wrongStmt, proof); err == nil {
		t.Fatal("AffGProof verified under wrong Paillier key")
	}

	primeStmt := stmt
	primeStmt.VerifierAux = primeRingPedersenFixture()
	if err := VerifyAffG(params, state, primeStmt, proof); err == nil {
		t.Fatal("AffGProof verified with prime VerifierAux modulus")
	}

	for _, tc := range []struct {
		name   string
		mutate func(*AffGProof)
	}{
		{name: "transcript", mutate: func(p *AffGProof) { p.TranscriptHash[0] ^= 1 }},
		{name: "A non unit", mutate: func(p *AffGProof) { p.A = new(big.Int).Set(stmt.VerifierAux.N) }},
		{name: "By nil", mutate: func(p *AffGProof) { p.By = nil }},
		{name: "E non unit", mutate: func(p *AffGProof) { p.E = new(big.Int).Set(stmt.ProverPaillierN.NSquared) }},
		{name: "S non unit", mutate: func(p *AffGProof) { p.S = new(big.Int).Set(stmt.VerifierAux.N) }},
		{name: "F non unit", mutate: func(p *AffGProof) { p.F = new(big.Int).Set(stmt.ProverPaillierN.NSquared) }},
		{name: "Y nil", mutate: func(p *AffGProof) { p.Y = nil }},
		{name: "z1 out of range", mutate: func(p *AffGProof) { p.Z1 = signedPowerOfTwo(params.EncRange() + 2) }},
		{name: "z2 non unit", mutate: func(p *AffGProof) { p.Z2 = new(big.Int).Set(stmt.ProverPaillierN.N) }},
		{name: "z3 out of range", mutate: func(p *AffGProof) { p.Z3 = multRangeOutside(stmt.VerifierAux.N, params.EncRange()+2) }},
		{name: "z4 out of range", mutate: func(p *AffGProof) { p.Z4 = signedPowerOfTwo(params.EncRange() + 2) }},
		{name: "equation 1", mutate: func(p *AffGProof) { p.A = new(big.Int).Add(p.A, big.NewInt(1)) }},
		{name: "equation 2", mutate: func(p *AffGProof) { p.S = new(big.Int).Add(p.S, big.NewInt(1)) }},
		{name: "equation 3", mutate: func(p *AffGProof) { p.E = new(big.Int).Add(p.E, big.NewInt(1)) }},
		{name: "y point relation", mutate: func(p *AffGProof) { p.YPoint = seedCurvePointBytes(81) }},
		{name: "alpha point relation", mutate: func(p *AffGProof) { p.AlphaPoint = seedCurvePointBytes(82) }},
		{name: "beta point commitment", mutate: func(p *AffGProof) { p.BetaPointCommitment = seedCurvePointBytes(83) }},
		{name: "product point commitment", mutate: func(p *AffGProof) { p.ProductPointCommitment = seedCurvePointBytes(84) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tampered := proof.Clone()
			tc.mutate(tampered)
			if err := VerifyAffG(params, state, stmt, tampered); err == nil {
				t.Fatal("tampered AffGProof verified")
			}
		})
	}

	badWitness := witness
	badWitness.X = testSecpSecretScalar(t, big.NewInt(24))
	if _, err := ProveAffG(params, state, stmt, badWitness, nil); err == nil {
		t.Fatal("AffGProof accepted witness that does not open statement")
	}
}

func TestLogStarProofVerificationMatrix(t *testing.T) {
	t.Parallel()
	params, stmt, witness, proof := logStarProofFixture(t)
	state := []byte("logstar matrix")
	if err := VerifyLogStar(params, state, stmt, proof); err != nil {
		t.Fatal(err)
	}
	if err := VerifyLogStar(params, []byte("other state"), stmt, proof); err == nil {
		t.Fatal("LogStarProof verified under wrong transcript state")
	}

	wrongKey := testPaillierKey(t, 1024)
	wrongStmt := stmt
	wrongStmt.PaillierN = wrongKey.PublicKey
	if err := VerifyLogStar(params, state, wrongStmt, proof); err == nil {
		t.Fatal("LogStarProof verified under wrong Paillier key")
	}

	// A VerifierAux with a prime modulus must be rejected.
	primeStmt := stmt
	primeStmt.VerifierAux = primeRingPedersenFixture()
	if err := VerifyLogStar(params, state, primeStmt, proof); err == nil {
		t.Fatal("LogStarProof verified with prime VerifierAux modulus")
	}

	for _, tc := range []struct {
		name   string
		mutate func(*LogStarProof)
	}{
		{name: "transcript", mutate: func(p *LogStarProof) { p.TranscriptHash[0] ^= 1 }},
		{name: "S non unit", mutate: func(p *LogStarProof) { p.S = new(big.Int).Set(stmt.VerifierAux.N) }},
		{name: "A invalid ciphertext", mutate: func(p *LogStarProof) { p.A = new(big.Int).Set(stmt.PaillierN.NSquared) }},
		{name: "Y nil", mutate: func(p *LogStarProof) { p.Y = nil }},
		{name: "D non unit", mutate: func(p *LogStarProof) { p.D = new(big.Int).Set(stmt.VerifierAux.N) }},
		{name: "z1 out of range", mutate: func(p *LogStarProof) { p.Z1 = signedPowerOfTwo(params.EncRange() + 2) }},
		{name: "z2 non unit", mutate: func(p *LogStarProof) { p.Z2 = new(big.Int).Set(stmt.PaillierN.N) }},
		{name: "z3 out of range", mutate: func(p *LogStarProof) { p.Z3 = multRangeOutside(stmt.VerifierAux.N, params.EncRange()+2) }},
		{name: "equation 1", mutate: func(p *LogStarProof) { p.A = new(big.Int).Add(p.A, big.NewInt(1)) }},
		{name: "equation 2", mutate: func(p *LogStarProof) { p.Y = seedCurvePoint(73) }},
		{name: "equation 3", mutate: func(p *LogStarProof) { p.D = new(big.Int).Add(p.D, big.NewInt(1)) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tampered := proof.Clone()
			tc.mutate(tampered)
			if err := VerifyLogStar(params, state, stmt, tampered); err == nil {
				t.Fatal("tampered LogStarProof verified")
			}
		})
	}

	badWitness := witness
	badWitness.X = testSecpSecretScalar(t, big.NewInt(32))
	if _, err := ProveLogStar(params, state, stmt, badWitness, nil); err == nil {
		t.Fatal("LogStarProof accepted witness that does not open statement")
	}
}

func TestProofsUseV1Version(t *testing.T) {
	t.Parallel()
	if encProofVersion != 1 || affGProofVersion != 1 || logStarProofVersion != 1 {
		t.Fatal("retained proof version changed")
	}
}
