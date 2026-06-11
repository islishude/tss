package paillier

import (
	"fmt"
	"math/big"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/wire"
)

// primeRingPedersenFixture returns a VerifierAux whose modulus is a 512-bit
// prime. ValidateRingPedersenParams (called by validateRPParamsForCommit)
// rejects prime moduli because Ring-Pedersen commitments require a composite N.
func primeRingPedersenFixture() RingPedersenParams {
	// 2^511 + 111, a 512-bit prime.
	primeN, ok := new(big.Int).SetString("6703903964971298549787012499102923063739682910296196688861780721860882015036773488400937149083451713845015929093243025426876941405973284973216824503042159", 10)
	if !ok {
		panic("failed to parse hardcoded prime")
	}
	return RingPedersenParams{
		N: primeN,
		S: big.NewInt(2),
		T: big.NewInt(3),
	}
}

func TestEncProofVerificationMatrix(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping crypto proof test in short mode")
	}
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
	wrongStmt.ProverPaillierN = &wrongKey.PublicKey
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
			tampered := cloneEncProof(proof)
			tc.mutate(tampered)
			if err := VerifyEnc(params, state, stmt, tampered); err == nil {
				t.Fatal("tampered EncProof verified")
			}
		})
	}

	badWitness := witness
	badWitness.K = new(big.Int).Add(witness.K, big.NewInt(1))
	if _, err := ProveEnc(params, state, stmt, badWitness, nil); err == nil {
		t.Fatal("EncProof accepted witness that does not open ciphertext")
	}
}

func TestAffGProofVerificationMatrix(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping crypto proof test in short mode")
	}
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
	wrongStmt.ProverPaillierN = &wrongKey.PublicKey
	if err := VerifyAffG(params, state, wrongStmt, proof); err == nil {
		t.Fatal("AffGProof verified under wrong prover Paillier key")
	}

	// A proof computed for one Y must not verify against a statement
	// that expects a different Y.
	wrongYStmt := stmt
	wrongYStmt.Y = new(big.Int).Add(stmt.Y, big.NewInt(1))
	if err := VerifyAffG(params, state, wrongYStmt, proof); err == nil {
		t.Fatal("AffGProof verified under wrong statement Y")
	}

	// A VerifierAux with a prime modulus must be rejected.
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
		{name: "A invalid ciphertext", mutate: func(p *AffGProof) { p.A = new(big.Int).Set(stmt.ReceiverPaillierN.NSquared) }},
		{name: "Bx nil", mutate: func(p *AffGProof) { p.Bx = nil }},
		{name: "By invalid ciphertext", mutate: func(p *AffGProof) { p.By = new(big.Int).Set(stmt.ProverPaillierN.NSquared) }},
		{name: "E non unit", mutate: func(p *AffGProof) { p.E = new(big.Int).Set(stmt.VerifierAux.N) }},
		{name: "S non unit", mutate: func(p *AffGProof) { p.S = new(big.Int).Set(stmt.VerifierAux.N) }},
		{name: "F non unit", mutate: func(p *AffGProof) { p.F = new(big.Int).Set(stmt.VerifierAux.N) }},
		{name: "T non unit", mutate: func(p *AffGProof) { p.T = new(big.Int).Set(stmt.VerifierAux.N) }},
		{name: "Y invalid ciphertext", mutate: func(p *AffGProof) { p.Y = new(big.Int).Set(stmt.ProverPaillierN.NSquared) }},
		{name: "z1 out of range", mutate: func(p *AffGProof) { p.Z1 = signedPowerOfTwo(params.EncRange() + 2) }},
		{name: "z2 out of range", mutate: func(p *AffGProof) { p.Z2 = signedPowerOfTwo(params.AffGRange() + 2) }},
		{name: "z3 out of range", mutate: func(p *AffGProof) { p.Z3 = multRangeOutside(stmt.VerifierAux.N, params.EncRange()+2) }},
		{name: "z4 out of range", mutate: func(p *AffGProof) { p.Z4 = multRangeOutside(stmt.VerifierAux.N, params.AffGRange()+2) }},
		{name: "w non unit", mutate: func(p *AffGProof) { p.W = new(big.Int).Set(stmt.ReceiverPaillierN.N) }},
		{name: "wY non unit", mutate: func(p *AffGProof) { p.WY = new(big.Int).Set(stmt.ProverPaillierN.N) }},
		{name: "equation 1", mutate: func(p *AffGProof) { p.A = new(big.Int).Add(p.A, big.NewInt(1)) }},
		{name: "equation 2", mutate: func(p *AffGProof) { p.Bx = seedCurvePoint(71) }},
		{name: "equation 3", mutate: func(p *AffGProof) { p.By = new(big.Int).Add(p.By, big.NewInt(1)) }},
		{name: "equation 4", mutate: func(p *AffGProof) { p.E = new(big.Int).Add(p.E, big.NewInt(1)) }},
		{name: "equation 5", mutate: func(p *AffGProof) { p.F = new(big.Int).Add(p.F, big.NewInt(1)) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tampered := cloneAffGProof(proof)
			tc.mutate(tampered)
			if err := VerifyAffG(params, state, stmt, tampered); err == nil {
				t.Fatal("tampered AffGProof verified")
			}
		})
	}

	badWitness := witness
	badWitness.X = new(big.Int).Add(witness.X, big.NewInt(1))
	if _, err := ProveAffG(params, state, stmt, badWitness, nil); err == nil {
		t.Fatal("AffGProof accepted witness that does not open statement")
	}
}

func TestLogStarProofVerificationMatrix(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping crypto proof test in short mode")
	}
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
	wrongStmt.PaillierN = &wrongKey.PublicKey
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
			tampered := cloneLogStarProof(proof)
			tc.mutate(tampered)
			if err := VerifyLogStar(params, state, stmt, tampered); err == nil {
				t.Fatal("tampered LogStarProof verified")
			}
		})
	}

	badWitness := witness
	badWitness.X = new(big.Int).Add(witness.X, big.NewInt(1))
	if _, err := ProveLogStar(params, state, stmt, badWitness, nil); err == nil {
		t.Fatal("LogStarProof accepted witness that does not open statement")
	}
}

func TestNewProofUnmarshalRejectsNonCanonicalSignedIntegers(t *testing.T) {
	for _, tc := range []struct {
		name      string
		raw       []byte
		wireType  string
		tags      []uint16
		unmarshal func([]byte) error
	}{
		{
			name:     "EncProof",
			raw:      mustMarshalBinary(t, seedEncProof()),
			wireType: encProofWireType,
			tags:     []uint16{encProofFieldZ1, encProofFieldZ3},
			unmarshal: func(raw []byte) error {
				_, err := UnmarshalEncProof(raw)
				return err
			},
		},
		{
			name:     "AffGProof",
			raw:      mustMarshalBinary(t, seedAffGProof(t)),
			wireType: affGProofWireType,
			tags:     []uint16{affGProofFieldZ1, affGProofFieldZ2, affGProofFieldZ3, affGProofFieldZ4},
			unmarshal: func(raw []byte) error {
				_, err := UnmarshalAffGProof(raw)
				return err
			},
		},
		{
			name:     "LogStarProof",
			raw:      mustMarshalBinary(t, seedLogStarProof()),
			wireType: logStarProofWireType,
			tags:     []uint16{logStarProofFieldZ1, logStarProofFieldZ3},
			unmarshal: func(raw []byte) error {
				_, err := UnmarshalLogStarProof(raw)
				return err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, tag := range tc.tags {
				t.Run(wireFieldName(tag), func(t *testing.T) {
					mutated, err := rewriteProofWireField(tc.raw, tc.wireType, tag, []byte{0x00, 0x00, 0x01})
					if err != nil {
						t.Fatal(err)
					}
					if err := tc.unmarshal(mutated); err == nil {
						t.Fatal("accepted non-canonical signed integer")
					}
				})
			}
		})
	}
}

func encProofFixture(t *testing.T) (SecurityParams, EncStatement, EncWitness, *EncProof) {
	t.Helper()
	params := fastProofParams()
	sk := testPaillierKey(t, 512)
	aux, _, err := GenerateRingPedersenParams(nil, sk)
	if err != nil {
		t.Fatal(err)
	}
	k := big.NewInt(17)
	ciphertext, rho, err := sk.Encrypt(nil, k)
	if err != nil {
		t.Fatal(err)
	}
	stmt := EncStatement{
		ProverPaillierN: &sk.PublicKey,
		CiphertextK:     ciphertext,
		VerifierAux:     *aux,
	}
	witness := EncWitness{K: k, Rho: rho}
	proof, err := ProveEnc(params, []byte("enc matrix"), stmt, witness, nil)
	if err != nil {
		t.Fatal(err)
	}
	return params, stmt, witness, proof
}

func affGProofFixture(t *testing.T) (SecurityParams, AffGStatement, AffGWitness, *AffGProof) {
	t.Helper()
	params := fastProofParams()
	sk := testPaillierKey(t, 512)
	aux, _, err := GenerateRingPedersenParams(nil, sk)
	if err != nil {
		t.Fatal(err)
	}
	x := big.NewInt(23)
	y := big.NewInt(29)
	c, _, err := sk.Encrypt(nil, x)
	if err != nil {
		t.Fatal(err)
	}
	encYReceiver, rho, err := sk.Encrypt(nil, y)
	if err != nil {
		t.Fatal(err)
	}
	xMulC, err := OMulCT(&sk.PublicKey, x, c, signedPowerOfTwoBytes(params.Ell))
	if err != nil {
		t.Fatal(err)
	}
	d, err := OAdd(&sk.PublicKey, xMulC, encYReceiver)
	if err != nil {
		t.Fatal(err)
	}
	proverY, rhoY, err := sk.Encrypt(nil, y)
	if err != nil {
		t.Fatal(err)
	}
	stmt := AffGStatement{
		ReceiverPaillierN: &sk.PublicKey,
		ProverPaillierN:   &sk.PublicKey,
		C:                 c,
		D:                 d,
		Y:                 proverY,
		X:                 secp.ScalarBaseMult(secp.ScalarFromBigInt(x)),
		VerifierAux:       *aux,
	}
	witness := AffGWitness{X: x, Y: y, Rho: rho, RhoY: rhoY}
	proof, err := ProveAffG(params, []byte("affg matrix"), stmt, witness, nil)
	if err != nil {
		t.Fatal(err)
	}
	return params, stmt, witness, proof
}

func logStarProofFixture(t *testing.T) (SecurityParams, LogStarStatement, LogStarWitness, *LogStarProof) {
	t.Helper()
	params := fastProofParams()
	sk := testPaillierKey(t, 512)
	aux, _, err := GenerateRingPedersenParams(nil, sk)
	if err != nil {
		t.Fatal(err)
	}
	x := big.NewInt(31)
	c, rho, err := sk.Encrypt(nil, x)
	if err != nil {
		t.Fatal(err)
	}
	base := secp.ScalarBaseMult(secp.ScalarFromBigInt(big.NewInt(1)))
	stmt := LogStarStatement{
		PaillierN:   &sk.PublicKey,
		C:           c,
		X:           secp.ScalarMult(base, secp.ScalarFromBigInt(x)),
		B:           base,
		VerifierAux: *aux,
	}
	witness := LogStarWitness{X: x, Rho: rho}
	proof, err := ProveLogStar(params, []byte("logstar matrix"), stmt, witness, nil)
	if err != nil {
		t.Fatal(err)
	}
	return params, stmt, witness, proof
}

func fastProofParams() SecurityParams {
	return SecurityParams{Ell: 256, EllPrime: 512, Epsilon: 64, ChallengeBits: 128, MinPaillierBits: 512}
}

func signedPowerOfTwo(bits uint) *big.Int {
	return new(big.Int).Lsh(big.NewInt(1), bits)
}

func multRangeOutside(n *big.Int, bits uint) *big.Int {
	out := new(big.Int).Lsh(big.NewInt(1), bits)
	out.Mul(out, n)
	return out
}

func cloneEncProof(in *EncProof) *EncProof {
	out := *in
	out.S = new(big.Int).Set(in.S)
	out.A = new(big.Int).Set(in.A)
	out.C = new(big.Int).Set(in.C)
	out.Z1 = new(big.Int).Set(in.Z1)
	out.Z2 = new(big.Int).Set(in.Z2)
	out.Z3 = new(big.Int).Set(in.Z3)
	out.TranscriptHash = append([]byte(nil), in.TranscriptHash...)
	return &out
}

func cloneAffGProof(in *AffGProof) *AffGProof {
	out := *in
	out.A = new(big.Int).Set(in.A)
	out.By = new(big.Int).Set(in.By)
	out.E = new(big.Int).Set(in.E)
	out.S = new(big.Int).Set(in.S)
	out.F = new(big.Int).Set(in.F)
	out.T = new(big.Int).Set(in.T)
	out.Y = new(big.Int).Set(in.Y)
	out.Z1 = new(big.Int).Set(in.Z1)
	out.Z2 = new(big.Int).Set(in.Z2)
	out.Z3 = new(big.Int).Set(in.Z3)
	out.Z4 = new(big.Int).Set(in.Z4)
	out.W = new(big.Int).Set(in.W)
	out.WY = new(big.Int).Set(in.WY)
	out.TranscriptHash = append([]byte(nil), in.TranscriptHash...)
	return &out
}

func cloneLogStarProof(in *LogStarProof) *LogStarProof {
	out := *in
	out.S = new(big.Int).Set(in.S)
	out.A = new(big.Int).Set(in.A)
	out.D = new(big.Int).Set(in.D)
	out.Z1 = new(big.Int).Set(in.Z1)
	out.Z2 = new(big.Int).Set(in.Z2)
	out.Z3 = new(big.Int).Set(in.Z3)
	out.TranscriptHash = append([]byte(nil), in.TranscriptHash...)
	return &out
}

func rewriteProofWireField(raw []byte, wireType string, tag uint16, value []byte) ([]byte, error) {
	version, fields, err := wire.UnmarshalFields(raw, wireType)
	if err != nil {
		return nil, err
	}
	for i := range fields {
		if fields[i].Tag == tag {
			fields[i].Value = append([]byte(nil), value...)
			return wire.MarshalFields(version, wireType, fields)
		}
	}
	return nil, fmt.Errorf("missing wire field %d", tag)
}

func wireFieldName(tag uint16) string {
	return fmt.Sprintf("field %d", tag)
}

// TestProofsUseV1Version verifies all proof types carry version 1.
func TestProofsUseV1Version(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 1024-bit Paillier proof version check in short mode")
	}
	sk := testPaillierKey(t, 1024)
	domain := []byte("version check")

	scalar := big.NewInt(3)
	c, r, _ := sk.Encrypt(nil, scalar)
	encProof, _ := ProveEncryption(nil, domain, &sk.PublicKey, c, scalar, r)
	if encProof.Version != 1 {
		t.Fatalf("encryption proof version %d, want 1", encProof.Version)
	}

	pt, _ := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(scalar)))
	logProof, _ := ProveLog(nil, domain, &sk.PublicKey, c, scalar, r, pt)
	if logProof.Version != 1 {
		t.Fatalf("log proof version %d, want 1", logProof.Version)
	}

	b := big.NewInt(5)
	beta := big.NewInt(11)
	bCom, _ := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(b)))
	resp, betaR := mtaResponseForTest(t, sk, c, b, beta)
	mtaProof, _ := ProveMTAResponse(nil, domain, &sk.PublicKey, c, resp, bCom, b, beta, betaR)
	if mtaProof.Version != 1 {
		t.Fatalf("MtA proof version %d, want 1", mtaProof.Version)
	}

	modProof, _ := ProveModulus(nil, domain, sk, 1)
	if modProof.Version != 1 {
		t.Fatalf("modulus proof version %d, want 1", modProof.Version)
	}

	params, lambda, _ := GenerateRingPedersenParams(nil, sk)
	rpProof, _ := ProveRingPedersen(nil, domain, sk, params, lambda, 1)
	if rpProof.Version != 1 {
		t.Fatalf("Ring-Pedersen proof version %d, want 1", rpProof.Version)
	}
}
