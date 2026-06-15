//go:build tier1

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

	t.Run("EncProof", func(t *testing.T) {
		params, stmt, _, proof := encProofFixture(t)
		state := []byte("enc matrix")
		if err := VerifyEnc(params, state, stmt, proof); err != nil {
			t.Fatal(err)
		}

		// z1 range: ±2^(EncRange+1). Set z1 to the bound — must be rejected.
		z1Bound := BoundUnsignedPowerOfTwo(params.EncRange() + 1)
		tampered := proof.Clone()
		tampered.Z1 = z1Bound
		if err := VerifyEnc(params, state, stmt, tampered); err == nil {
			t.Fatal("z1 at exact range bound should be rejected by range check")
		}

		// z1 far out of range
		tampered = proof.Clone()
		tampered.Z1 = BoundUnsignedPowerOfTwo(params.EncRange() + 2)
		if err := VerifyEnc(params, state, stmt, tampered); err == nil {
			t.Fatal("z1 far out of range should be rejected by range check")
		}

		// z3 range: ±N·2^(EncRange+1) — test just above
		z3Above := BoundUnsignedPowerOfTwo(params.EncRange() + 1)
		z3Above.Mul(z3Above, stmt.VerifierAux.N)
		z3Above.Add(z3Above, big.NewInt(1))
		tampered = proof.Clone()
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
		z1Bound := BoundUnsignedPowerOfTwo(params.EncRange() + 1)
		tampered := proof.Clone()
		tampered.Z1 = z1Bound
		if err := VerifyAffG(params, state, stmt, tampered); err == nil {
			t.Fatal("z1 at exact range bound should be rejected by range check")
		}

		// z2 range: ±2^(AffGRange+1)
		z2Bound := BoundUnsignedPowerOfTwo(params.AffGRange() + 1)
		tampered = proof.Clone()
		tampered.Z2 = z2Bound
		if err := VerifyAffG(params, state, stmt, tampered); err == nil {
			t.Fatal("z2 at exact range bound should be rejected by range check")
		}

		// z3 range: ±Nhat·2^(EncRange+1) — just above
		z3Above := BoundUnsignedPowerOfTwo(params.EncRange() + 1)
		z3Above.Mul(z3Above, stmt.VerifierAux.N)
		z3Above.Add(z3Above, big.NewInt(1))
		tampered = proof.Clone()
		tampered.Z3 = z3Above
		if err := VerifyAffG(params, state, stmt, tampered); err == nil {
			t.Fatal("z3 above range bound should be rejected")
		}

		// z4 range: ±Nhat·2^(AffGRange+1) — just above
		z4Above := BoundUnsignedPowerOfTwo(params.AffGRange() + 1)
		z4Above.Mul(z4Above, stmt.VerifierAux.N)
		z4Above.Add(z4Above, big.NewInt(1))
		tampered = proof.Clone()
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
		z1Bound := BoundUnsignedPowerOfTwo(params.EncRange() + 1)
		tampered := proof.Clone()
		tampered.Z1 = z1Bound
		if err := VerifyLogStar(params, state, stmt, tampered); err == nil {
			t.Fatal("z1 at exact range bound should be rejected by range check")
		}

		// z3 range: ±N·2^(EncRange+1) — just above
		z3Above := BoundUnsignedPowerOfTwo(params.EncRange() + 1)
		z3Above.Mul(z3Above, stmt.VerifierAux.N)
		z3Above.Add(z3Above, big.NewInt(1))
		tampered = proof.Clone()
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
		tampered := proof.Clone()
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

		tampered := proof.Clone()
		tampered.Response = intBytes(bound)
		if VerifyLog(domain, &sk.PublicKey, ciphertext, tampered) {
			t.Fatal("log proof with response at range bound should be rejected")
		}
	})
}
