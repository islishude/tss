package paillier

import (
	"bytes"
	"math/big"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
)

func TestIdentificationProofsCorrectness(t *testing.T) {
	params := fastProofParams()
	sk := testPaillierKey(t, 512)
	aux, lambda, err := GenerateRingPedersenParams(nil, sk)
	if err != nil {
		t.Fatal(err)
	}
	lambda.Destroy()
	state := []byte("identification/domain")

	x := testSecpSecretScalar(t, big.NewInt(7))
	xCipher, rhoX, err := sk.EncryptSecret(nil, x)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rhoX.Destroy)
	yCipher, _, err := sk.Encrypt(nil, big.NewInt(11))
	if err != nil {
		t.Fatal(err)
	}
	_, rhoC, err := sk.Encrypt(nil, big.NewInt(0))
	if err != nil {
		t.Fatal(err)
	}
	rhoCSecret := testSecretScalarFixed(t, rhoC, (sk.N.BitLen()+7)/8)
	xSigned, err := signedSecretFromScalar(x, secp.ScalarSize)
	if err != nil {
		t.Fatal(err)
	}
	defer xSigned.Destroy()
	product, err := OMulCT(sk.PublicKey, xSigned, yCipher, secp.ScalarSize)
	if err != nil {
		t.Fatal(err)
	}
	zero, err := EncRandom(sk.PublicKey, big.NewInt(0), rhoC)
	if err != nil {
		t.Fatal(err)
	}
	product, err = OAdd(sk.PublicKey, product, zero)
	if err != nil {
		t.Fatal(err)
	}
	mulStmt := MulStatement{PaillierN: sk.PublicKey, X: xCipher, Y: yCipher, C: product}
	mulProof, err := ProveMul(params, state, mulStmt, MulWitness{X: x, RhoX: rhoX, RhoC: rhoCSecret}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyMul(params, state, mulStmt, mulProof); err != nil {
		t.Fatal(err)
	}
	mulRaw, err := mulProof.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var decodedMul MulProof
	if err := decodedMul.UnmarshalBinary(mulRaw); err != nil {
		t.Fatal(err)
	}
	if err := VerifyMul(params, state, mulStmt, &decodedMul); err != nil {
		t.Fatal(err)
	}
	mulMutations := []func(*MulProof){
		func(p *MulProof) { p.A.Add(p.A, big.NewInt(1)) },
		func(p *MulProof) { p.B.Add(p.B, big.NewInt(1)) },
		func(p *MulProof) { p.Z.Add(p.Z, big.NewInt(1)) },
		func(p *MulProof) { p.U.Add(p.U, big.NewInt(1)) },
		func(p *MulProof) { p.V.Add(p.V, big.NewInt(1)) },
		func(p *MulProof) { p.TranscriptHash[0] ^= 1 },
	}
	for i, mutate := range mulMutations {
		candidate := mulProof.Clone()
		mutate(candidate)
		if VerifyMul(params, state, mulStmt, candidate) == nil {
			t.Fatalf("MulProof mutation %d verified", i)
		}
		candidate.Destroy()
	}
	if VerifyMul(params, []byte("wrong-domain"), mulStmt, mulProof) == nil {
		t.Fatal("MulProof accepted wrong domain")
	}

	base := secp.ScalarBaseMult(secp.ScalarOne())
	mulStarStmt := MulStarStatement{
		PaillierN:   sk.PublicKey,
		C:           yCipher,
		D:           product,
		X:           secp.ScalarMult(base, secp.ScalarFromBigInt(big.NewInt(7))),
		B:           base,
		VerifierAux: aux,
	}
	mulStarProof, err := ProveMulStar(params, state, mulStarStmt, MulStarWitness{X: x, Rho: rhoCSecret}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyMulStar(params, state, mulStarStmt, mulStarProof); err != nil {
		t.Fatal(err)
	}
	mulStarMutations := []func(*MulStarProof){
		func(p *MulStarProof) { p.A.Add(p.A, big.NewInt(1)) },
		func(p *MulStarProof) { p.Bx = secp.ScalarBaseMult(secp.ScalarFromUint64(2)) },
		func(p *MulStarProof) { p.S.Add(p.S, big.NewInt(1)) },
		func(p *MulStarProof) { p.E.Add(p.E, big.NewInt(1)) },
		func(p *MulStarProof) { p.Z1.Add(p.Z1, big.NewInt(1)) },
		func(p *MulStarProof) { p.Z2.Add(p.Z2, big.NewInt(1)) },
		func(p *MulStarProof) { p.W.Add(p.W, big.NewInt(1)) },
		func(p *MulStarProof) { p.TranscriptHash[0] ^= 1 },
	}
	for i, mutate := range mulStarMutations {
		candidate := mulStarProof.Clone()
		mutate(candidate)
		if VerifyMulStar(params, state, mulStarStmt, candidate) == nil {
			t.Fatalf("MulStarProof mutation %d verified", i)
		}
		candidate.Destroy()
	}
	if VerifyMulStar(params, []byte("wrong-domain"), mulStarStmt, mulStarProof) == nil {
		t.Fatal("MulStarProof accepted wrong domain")
	}

	y := testSignedSecret(t, big.NewInt(-19), 64)
	ciphertext, randomness, err := sk.Encrypt(nil, big.NewInt(-19))
	if err != nil {
		t.Fatal(err)
	}
	randomnessSecret := testSecretScalarFixed(t, randomness, (sk.N.BitLen()+7)/8)
	decStmt := DecStatement{PaillierN: sk.PublicKey, C: ciphertext, X: secp.ScalarFromBigInt(big.NewInt(-19)), VerifierAux: aux}
	decProof, err := ProveDec(params, state, decStmt, DecWitness{Y: y, Rho: randomnessSecret}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDec(params, state, decStmt, decProof); err != nil {
		t.Fatal(err)
	}
	decMutations := []func(*DecProof){
		func(p *DecProof) { p.S.Add(p.S, big.NewInt(1)) },
		func(p *DecProof) { p.T.Add(p.T, big.NewInt(1)) },
		func(p *DecProof) { p.A.Add(p.A, big.NewInt(1)) },
		func(p *DecProof) { p.Gamma[0] ^= 1 },
		func(p *DecProof) { p.Z1.Add(p.Z1, big.NewInt(1)) },
		func(p *DecProof) { p.Z2.Add(p.Z2, big.NewInt(1)) },
		func(p *DecProof) { p.W.Add(p.W, big.NewInt(1)) },
		func(p *DecProof) { p.TranscriptHash[0] ^= 1 },
	}
	for i, mutate := range decMutations {
		candidate := decProof.Clone()
		mutate(candidate)
		if VerifyDec(params, state, decStmt, candidate) == nil {
			t.Fatalf("DecProof mutation %d verified", i)
		}
		candidate.Destroy()
	}
	tooLarge := decProof.Clone()
	tooLarge.Z1 = new(big.Int).Lsh(big.NewInt(1), uint(params.DecRange()+2))
	if VerifyDec(params, state, decStmt, tooLarge) == nil {
		t.Fatal("DecProof accepted out-of-range response")
	}
	tooLarge.Destroy()
}

func TestIdentificationProofsRejectMutationAndWrongDomain(t *testing.T) {
	params := fastProofParams()
	sk := testPaillierKey(t, 512)
	aux, lambda, err := GenerateRingPedersenParams(nil, sk)
	if err != nil {
		t.Fatal(err)
	}
	lambda.Destroy()
	y := testSignedSecret(t, big.NewInt(23), 64)
	ciphertext, randomness, err := sk.Encrypt(nil, big.NewInt(23))
	if err != nil {
		t.Fatal(err)
	}
	randomnessSecret := testSecretScalarFixed(t, randomness, (sk.N.BitLen()+7)/8)
	stmt := DecStatement{PaillierN: sk.PublicKey, C: ciphertext, X: secp.ScalarFromBigInt(big.NewInt(23)), VerifierAux: aux}
	proof, err := ProveDec(params, []byte("right"), stmt, DecWitness{Y: y, Rho: randomnessSecret}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if VerifyDec(params, []byte("wrong"), stmt, proof) == nil {
		t.Fatal("DecProof accepted wrong domain")
	}
	mutated := proof.Clone()
	mutated.Z1.Add(mutated.Z1, big.NewInt(1))
	if VerifyDec(params, []byte("right"), stmt, mutated) == nil {
		t.Fatal("DecProof accepted mutated response")
	}
}

func FuzzIdentificationProofDecoders(f *testing.F) {
	point := secp.ScalarBaseMult(secp.ScalarOne())
	transcriptHash := make([]byte, 32)
	seeds := [][]byte{}
	mul := &MulProof{A: big.NewInt(1), B: big.NewInt(2), Z: big.NewInt(3), U: big.NewInt(4), V: big.NewInt(5), TranscriptHash: transcriptHash}
	if raw, err := mul.MarshalBinary(); err == nil {
		seeds = append(seeds, raw)
	}
	mulStar := &MulStarProof{A: big.NewInt(1), Bx: point, S: big.NewInt(2), E: big.NewInt(3), Z1: big.NewInt(4), Z2: big.NewInt(5), W: big.NewInt(6), TranscriptHash: transcriptHash}
	if raw, err := mulStar.MarshalBinary(); err == nil {
		seeds = append(seeds, raw)
	}
	dec := &DecProof{S: big.NewInt(1), T: big.NewInt(2), A: big.NewInt(3), Gamma: make([]byte, secp.ScalarSize), Z1: big.NewInt(4), Z2: big.NewInt(5), W: big.NewInt(6), TranscriptHash: transcriptHash}
	if raw, err := dec.MarshalBinary(); err == nil {
		seeds = append(seeds, raw)
	}
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		decoders := []interface {
			UnmarshalBinary([]byte) error
			MarshalBinary() ([]byte, error)
		}{&MulProof{}, &MulStarProof{}, &DecProof{}}
		for _, decoder := range decoders {
			if err := decoder.UnmarshalBinary(raw); err != nil {
				continue
			}
			canonical, err := decoder.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(canonical, raw) {
				t.Fatal("accepted non-canonical identification proof encoding")
			}
		}
	})
}
