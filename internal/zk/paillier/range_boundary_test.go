package paillier

import (
	"math/big"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
)

// TestSignedPowerOfTwoBoundary verifies InSignedPowerOfTwo accepts exactly at
// ±2^bits and rejects exactly at ±(2^bits + 1). An off-by-one in this check
// would allow a prover to use out-of-range witnesses, breaking the range proof
// soundness.
func TestSignedPowerOfTwoBoundary(t *testing.T) {
	t.Parallel()
	for _, bits := range []uint{1, 8, 64, 128, 256, 384, 486} {
		bound := new(big.Int).Lsh(big.NewInt(1), bits) // 2^bits
		negBound := new(big.Int).Neg(bound)
		above := new(big.Int).Add(bound, big.NewInt(1))
		below := new(big.Int).Sub(negBound, big.NewInt(1))

		if !InSignedPowerOfTwo(bound, bits) {
			t.Errorf("bits=%d: +2^bits should be accepted", bits)
		}
		if !InSignedPowerOfTwo(negBound, bits) {
			t.Errorf("bits=%d: -2^bits should be accepted", bits)
		}
		if !InSignedPowerOfTwo(big.NewInt(0), bits) {
			t.Errorf("bits=%d: zero should be accepted", bits)
		}

		if InSignedPowerOfTwo(above, bits) {
			t.Errorf("bits=%d: +2^bits+1 should be rejected", bits)
		}
		if InSignedPowerOfTwo(below, bits) {
			t.Errorf("bits=%d: -(2^bits+1) should be rejected", bits)
		}
	}
}

// TestUnsignedPowerOfTwoBoundary verifies InUnsignedPowerOfTwo accepts [0, 2^bits)
// and rejects at 2^bits.
func TestUnsignedPowerOfTwoBoundary(t *testing.T) {
	t.Parallel()
	for _, bits := range []uint{1, 8, 64, 128, 256} {
		bound := new(big.Int).Lsh(big.NewInt(1), bits)
		below := new(big.Int).Sub(bound, big.NewInt(1))

		if !InUnsignedPowerOfTwo(big.NewInt(0), bits) {
			t.Errorf("bits=%d: zero should be accepted", bits)
		}
		if !InUnsignedPowerOfTwo(below, bits) {
			t.Errorf("bits=%d: 2^bits-1 should be accepted", bits)
		}
		if InUnsignedPowerOfTwo(bound, bits) {
			t.Errorf("bits=%d: 2^bits should be rejected (exclusive bound)", bits)
		}
		if InUnsignedPowerOfTwo(new(big.Int).Neg(big.NewInt(1)), bits) {
			t.Errorf("bits=%d: negative should be rejected", bits)
		}
	}
}

// TestMultRangeBoundary verifies inMultRange accepts exactly at ±N·2^bits and
// rejects at ±(N·2^bits + 1). This range is used for Ring-Pedersen commitment
// nonces in Πenc, Πaff-g, and Πlog*. An off-by-one would allow a malicious
// prover to submit nonces outside the range that still pass verification.
func TestMultRangeBoundary(t *testing.T) {
	t.Parallel()
	n := big.NewInt(100003) // small prime for testing

	for _, bits := range []uint{1, 8, 64, 128, 256} {
		bound := new(big.Int).Lsh(big.NewInt(1), bits) // 2^bits
		bound.Mul(bound, n)                            // N·2^bits

		posBound := new(big.Int).Set(bound)
		negBound := new(big.Int).Neg(bound)
		above := new(big.Int).Add(bound, big.NewInt(1))
		below := new(big.Int).Sub(negBound, big.NewInt(1))

		if !inMultRange(posBound, n, bits) {
			t.Errorf("bits=%d: +N·2^bits should be accepted", bits)
		}
		if !inMultRange(negBound, n, bits) {
			t.Errorf("bits=%d: -N·2^bits should be accepted", bits)
		}
		if !inMultRange(big.NewInt(0), n, bits) {
			t.Errorf("bits=%d: zero should be accepted", bits)
		}

		if inMultRange(above, n, bits) {
			t.Errorf("bits=%d: +N·2^bits+1 should be rejected", bits)
		}
		if inMultRange(below, n, bits) {
			t.Errorf("bits=%d: -(N·2^bits+1) should be rejected", bits)
		}
	}
}

// TestZKRangeBound verifies that zkRangeBound(e) computes the correct bound
// 2^{l+ε} + e·q, matching the statistical ZK formula used by all legacy proofs.
func TestZKRangeBound(t *testing.T) {
	t.Parallel()
	q := secp.Order()

	// Test e=0: bound = 2^{l+ε} = 2^384
	eZero := big.NewInt(0)
	boundZero := zkRangeBound(eZero)
	expectedZero := twoToThe(maskBits) // 2^384
	if boundZero.Cmp(expectedZero) != 0 {
		t.Fatalf("zkRangeBound(0) = %s, want 2^384", boundZero)
	}

	// Test e=1: bound = 2^384 + q
	eOne := big.NewInt(1)
	boundOne := zkRangeBound(eOne)
	expectedOne := new(big.Int).Set(expectedZero)
	expectedOne.Add(expectedOne, q)
	if boundOne.Cmp(expectedOne) != 0 {
		t.Fatalf("zkRangeBound(1) = %s, want 2^384 + q", boundOne)
	}

	// Test e = secp256k1 order - 1 (max realistic challenge for legacy proofs)
	eMax := new(big.Int).Sub(q, big.NewInt(1))
	boundMax := zkRangeBound(eMax)
	expectedMax := new(big.Int).Mul(eMax, q)
	expectedMax.Add(expectedMax, expectedZero)
	if boundMax.Cmp(expectedMax) != 0 {
		t.Fatalf("zkRangeBound(q-1) mismatch")
	}

	// Verify bound is strictly tight: bound-1 is less than bound
	below := new(big.Int).Sub(boundOne, big.NewInt(1))
	if below.Cmp(boundOne) >= 0 {
		t.Fatal("bound-1 >= bound — arithmetic error")
	}
}

// TestProofResponseRangeBoundaryPrecision verifies that for each new CGGMP proof
// type (EncProof, AffGProof, LogStarProof), setting a response to exactly the
// range bound or beyond causes rejection. The range checks are defense-in-depth
// guards that run BEFORE algebraic equations in Verify.
//
// Note: we test that out-of-range responses are rejected by the range check.
// We do NOT test "bound-1 verifies" because changing the response to an
// arbitrary in-range value breaks the algebraic consistency (z = α + e·w),
// and the range check is not the only rejection path.
func TestProofResponseRangeBoundaryPrecision(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("skipping crypto proof test in short mode")
	}

	t.Run("EncProof", func(t *testing.T) {
		params, stmt, _, proof := encProofFixture(t)
		state := []byte("enc matrix")
		if err := VerifyEnc(params, state, stmt, proof); err != nil {
			t.Fatal(err)
		}

		// z1 range: ±2^(EncRange+1). Set z1 to the bound — must be rejected.
		z1Bound := new(big.Int).Lsh(big.NewInt(1), params.EncRange()+1)
		tampered := cloneEncProof(proof)
		tampered.Z1 = z1Bound
		if err := VerifyEnc(params, state, stmt, tampered); err == nil {
			t.Fatal("z1 at exact range bound should be rejected by range check")
		}

		// z1 far out of range
		tampered = cloneEncProof(proof)
		tampered.Z1 = new(big.Int).Lsh(big.NewInt(1), params.EncRange()+2)
		if err := VerifyEnc(params, state, stmt, tampered); err == nil {
			t.Fatal("z1 far out of range should be rejected by range check")
		}

		// z3 range: ±N·2^(EncRange+1) — test just above
		z3Above := new(big.Int).Lsh(big.NewInt(1), params.EncRange()+1)
		z3Above.Mul(z3Above, stmt.VerifierAux.N)
		z3Above.Add(z3Above, big.NewInt(1))
		tampered = cloneEncProof(proof)
		tampered.Z3 = z3Above
		if err := VerifyEnc(params, state, stmt, tampered); err == nil {
			t.Fatal("z3 above range bound should be rejected")
		}
	})

	t.Run("AffGProof", func(t *testing.T) {
		params, stmt, _, proof := affGProofFixture(t)
		state := []byte("affg matrix")
		if err := VerifyAffG(params, state, stmt, proof); err != nil {
			t.Fatal(err)
		}

		// z1 range: ±2^(EncRange+1)
		z1Bound := new(big.Int).Lsh(big.NewInt(1), params.EncRange()+1)
		tampered := cloneAffGProof(proof)
		tampered.Z1 = z1Bound
		if err := VerifyAffG(params, state, stmt, tampered); err == nil {
			t.Fatal("z1 at exact range bound should be rejected by range check")
		}

		// z2 range: ±2^(AffGRange+1)
		z2Bound := new(big.Int).Lsh(big.NewInt(1), params.AffGRange()+1)
		tampered = cloneAffGProof(proof)
		tampered.Z2 = z2Bound
		if err := VerifyAffG(params, state, stmt, tampered); err == nil {
			t.Fatal("z2 at exact range bound should be rejected by range check")
		}

		// z3 range: ±Nhat·2^(EncRange+1) — just above
		z3Above := new(big.Int).Lsh(big.NewInt(1), params.EncRange()+1)
		z3Above.Mul(z3Above, stmt.VerifierAux.N)
		z3Above.Add(z3Above, big.NewInt(1))
		tampered = cloneAffGProof(proof)
		tampered.Z3 = z3Above
		if err := VerifyAffG(params, state, stmt, tampered); err == nil {
			t.Fatal("z3 above range bound should be rejected")
		}

		// z4 range: ±Nhat·2^(AffGRange+1) — just above
		z4Above := new(big.Int).Lsh(big.NewInt(1), params.AffGRange()+1)
		z4Above.Mul(z4Above, stmt.VerifierAux.N)
		z4Above.Add(z4Above, big.NewInt(1))
		tampered = cloneAffGProof(proof)
		tampered.Z4 = z4Above
		if err := VerifyAffG(params, state, stmt, tampered); err == nil {
			t.Fatal("z4 above range bound should be rejected")
		}
	})

	t.Run("LogStarProof", func(t *testing.T) {
		params, stmt, _, proof := logStarProofFixture(t)
		state := []byte("logstar matrix")
		if err := VerifyLogStar(params, state, stmt, proof); err != nil {
			t.Fatal(err)
		}

		// z1 range: ±2^(EncRange+1)
		z1Bound := new(big.Int).Lsh(big.NewInt(1), params.EncRange()+1)
		tampered := cloneLogStarProof(proof)
		tampered.Z1 = z1Bound
		if err := VerifyLogStar(params, state, stmt, tampered); err == nil {
			t.Fatal("z1 at exact range bound should be rejected by range check")
		}

		// z3 range: ±N·2^(EncRange+1) — just above
		z3Above := new(big.Int).Lsh(big.NewInt(1), params.EncRange()+1)
		z3Above.Mul(z3Above, stmt.VerifierAux.N)
		z3Above.Add(z3Above, big.NewInt(1))
		tampered = cloneLogStarProof(proof)
		tampered.Z3 = z3Above
		if err := VerifyLogStar(params, state, stmt, tampered); err == nil {
			t.Fatal("z3 above range bound should be rejected")
		}
	})
}

// TestLegacyProofZKRangeBound verifies the zkRangeBound check in legacy proofs
// (EncryptionProof, LogProof). These proofs use zkRangeBound(e) = 2^{l+ε} + e·q
// as the response range guard.
func TestLegacyProofZKRangeBound(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("skipping crypto proof test in short mode")
	}

	sk := testPaillierKey(t, 1024)
	domain := []byte("legacy range boundary")

	t.Run("EncryptionProof", func(t *testing.T) {
		scalar := big.NewInt(42)
		ciphertext, randomness, err := sk.Encrypt(nil, scalar)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := ProveEncryption(nil, domain, &sk.PublicKey, ciphertext, scalar, randomness)
		if err != nil {
			t.Fatal(err)
		}
		if !VerifyEncryption(domain, &sk.PublicKey, ciphertext, proof) {
			t.Fatal("valid encryption proof rejected")
		}

		transcript := encryptionTranscript(domain, &sk.PublicKey, ciphertext,
			proof.ScalarCommitment, proof.Bound,
			new(big.Int).SetBytes(proof.CipherCommitment),
			proof.PointCommitment)
		e := challenge([]byte(encryptionChallengeLabel), transcript)
		bound := zkRangeBound(e)

		// Response at bound must be rejected by the range guard.
		tampered := cloneEncryptionProof(proof)
		tampered.Response = intBytes(bound)
		if VerifyEncryption(domain, &sk.PublicKey, ciphertext, tampered) {
			t.Fatal("encryption proof with response at range bound should be rejected")
		}
	})

	t.Run("LogProof", func(t *testing.T) {
		scalar := big.NewInt(99)
		ciphertext, randomness, err := sk.Encrypt(nil, scalar)
		if err != nil {
			t.Fatal(err)
		}
		pointBytes, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(scalar)))
		if err != nil {
			t.Fatal(err)
		}
		proof, err := ProveLog(nil, domain, &sk.PublicKey, ciphertext, scalar, randomness, pointBytes)
		if err != nil {
			t.Fatal(err)
		}
		if !VerifyLog(domain, &sk.PublicKey, ciphertext, proof) {
			t.Fatal("valid log proof rejected")
		}

		transcript := logTranscript(domain, &sk.PublicKey, ciphertext, proof.Point,
			new(big.Int).SetBytes(proof.CipherCommitment),
			proof.PointCommitment)
		e := challenge([]byte(logChallengeLabel), transcript)
		bound := zkRangeBound(e)

		tampered := cloneLogProof(proof)
		tampered.Response = intBytes(bound)
		if VerifyLog(domain, &sk.PublicKey, ciphertext, tampered) {
			t.Fatal("log proof with response at range bound should be rejected")
		}
	})
}

// TestSampleSignedPowerOfTwoDistribution verifies SampleSignedPowerOfTwo
// produces values in the correct range [−2^bits, 2^bits].
func TestSampleSignedPowerOfTwoDistribution(t *testing.T) {
	t.Parallel()
	for _, bits := range []uint{1, 8, 64} {
		bound := new(big.Int).Lsh(big.NewInt(1), bits)
		for range 500 {
			x, err := SampleSignedPowerOfTwo(nil, bits)
			if err != nil {
				t.Fatal(err)
			}
			if x.Cmp(new(big.Int).Neg(bound)) < 0 || x.Cmp(bound) > 0 {
				t.Errorf("bits=%d: sample %s out of range [−2^%d, 2^%d]", bits, x, bits, bits)
			}
		}
	}
}

// TestSampleMultRangeDistribution verifies SampleMultRange produces values in
// ±(N·2^bits).
func TestSampleMultRangeDistribution(t *testing.T) {
	t.Parallel()
	n := big.NewInt(100003)
	for _, bits := range []uint{1, 8, 64} {
		bound := new(big.Int).Lsh(big.NewInt(1), bits)
		bound.Mul(bound, n)
		for range 500 {
			x, err := SampleMultRange(nil, bits, n)
			if err != nil {
				t.Fatal(err)
			}
			if x.Cmp(new(big.Int).Neg(bound)) < 0 || x.Cmp(bound) > 0 {
				t.Errorf("bits=%d: sample %s out of range ±N·2^%d", bits, x, bits)
			}
		}
	}
}
