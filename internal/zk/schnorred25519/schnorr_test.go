package schnorred25519

import (
	"bytes"
	"errors"
	"io"
	"math/big"
	"slices"
	"testing"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/testutil"
	"github.com/islishude/tss/internal/wire"
)

const testPointSize = 32

func testSecretScalar(t *testing.T, value uint64) *secret.Scalar {
	t.Helper()
	scalar := edcurve.ScalarFromUint64(value)
	encoded := scalar.Bytes()
	scalar.Set(fed.NewScalar())
	out, err := secret.NewScalar(encoded, edcurve.ScalarSize)
	clear(encoded)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(out.Destroy)
	return out
}

func testSecretFromBytes(t *testing.T, encoded []byte, fixedLen int) *secret.Scalar {
	t.Helper()
	out, err := secret.NewScalar(encoded, fixedLen)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(out.Destroy)
	return out
}

func testPublic(t *testing.T, value uint64) []byte {
	t.Helper()
	scalar := edcurve.ScalarFromUint64(value)
	defer scalar.Set(fed.NewScalar())
	return fed.NewIdentityPoint().ScalarBaseMult(scalar).Bytes()
}

func littleEndianScalar(value *big.Int) []byte {
	encoded := value.FillBytes(make([]byte, edcurve.ScalarSize))
	slices.Reverse(encoded)
	return encoded
}

func testProof(t *testing.T) (*Proof, []byte) {
	t.Helper()
	proof, public, err := ProveWithReader(
		testutil.DeterministicReader(7301),
		[]byte("ed25519-schnorr-test-domain"),
		testSecretScalar(t, 13),
	)
	if err != nil {
		t.Fatal(err)
	}
	return proof, public
}

func TestProofDeterministicProveVerifyAndEncoding(t *testing.T) {
	t.Parallel()

	domain := []byte("ed25519-schnorr-test-domain")
	proof, public := testProof(t)
	proofAgain, publicAgain, err := ProveWithReader(
		testutil.DeterministicReader(7301),
		domain,
		testSecretScalar(t, 13),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(public, publicAgain) || !bytes.Equal(proof.Commitment, proofAgain.Commitment) || !bytes.Equal(proof.Response, proofAgain.Response) {
		t.Fatal("same secret, domain, and deterministic reader produced a different proof")
	}
	if !Verify(domain, public, proof) {
		t.Fatal("valid proof did not verify")
	}
	if Verify([]byte("wrong-domain"), public, proof) {
		t.Fatal("proof verified under the wrong domain")
	}
	if proof.WireType() != proofWireType || proof.WireVersion() != proofWireVersion {
		t.Fatal("proof reported the wrong wire identity")
	}

	raw, err := proof.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	rawAgain, err := proof.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, rawAgain) {
		t.Fatal("proof encoding is not deterministic")
	}
	wireValue, err := proof.MarshalWireValue()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, wireValue) {
		t.Fatal("proof custom wire value differs from its canonical message")
	}

	decoded, err := tss.DecodeBinary[Proof](raw)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(domain, public, decoded) {
		t.Fatal("decoded proof did not verify")
	}
	var decodedValue Proof
	if err := decodedValue.UnmarshalWireValue(raw); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decodedValue.Commitment, proof.Commitment) || !bytes.Equal(decodedValue.Response, proof.Response) {
		t.Fatal("custom wire value did not round trip")
	}
	if _, err := tss.DecodeBinary[Proof]([]byte(`{"commitment":"not-tlv"}`)); err == nil {
		t.Fatal("JSON proof decoded")
	}
	if _, err := tss.DecodeBinary[Proof](append(bytes.Clone(raw), 0)); err == nil {
		t.Fatal("proof with trailing data decoded")
	}

	clone := proof.Clone()
	clone.Commitment[0] ^= 1
	clone.Response[0] ^= 1
	if bytes.Equal(clone.Commitment, proof.Commitment) || bytes.Equal(clone.Response, proof.Response) {
		t.Fatal("proof clone aliases its source")
	}
	if (*Proof)(nil).Clone() != nil {
		t.Fatal("nil proof clone was non-nil")
	}
}

func TestProofNestedRecordRoundTrip(t *testing.T) {
	t.Parallel()

	proof, public := testProof(t)
	container := proofContainer{Proof: proof}
	raw, err := wire.Marshal(container)
	if err != nil {
		t.Fatal(err)
	}
	var decoded proofContainer
	if err := wire.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Proof == nil || !Verify([]byte("ed25519-schnorr-test-domain"), public, decoded.Proof) {
		t.Fatal("nested record proof did not round trip or verify")
	}
}

func TestChallengeBindsDomainPublicAndCommitment(t *testing.T) {
	t.Parallel()

	domain := []byte("domain-a")
	public := testPublic(t, 13)
	commitment := testPublic(t, 29)
	base, err := challenge(domain, public, commitment)
	if err != nil {
		t.Fatal(err)
	}
	defer base.Set(fed.NewScalar())
	if base.Equal(fed.NewScalar()) == 1 {
		t.Fatal("challenge was zero")
	}
	if _, err := edcurve.ScalarFromCanonical(base.Bytes()); err != nil {
		t.Fatalf("challenge was not canonical: %v", err)
	}

	tests := []struct {
		name       string
		domain     []byte
		public     []byte
		commitment []byte
	}{
		{name: "outer domain", domain: []byte("domain-b"), public: public, commitment: commitment},
		{name: "public key", domain: domain, public: testPublic(t, 17), commitment: commitment},
		{name: "commitment", domain: domain, public: public, commitment: testPublic(t, 31)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			changed, err := challenge(tc.domain, tc.public, tc.commitment)
			if err != nil {
				t.Fatal(err)
			}
			defer changed.Set(fed.NewScalar())
			if base.Equal(changed) == 1 {
				t.Fatal("challenge field substitution did not change the challenge")
			}
		})
	}
}

func TestProofTamperingDoesNotVerify(t *testing.T) {
	t.Parallel()

	domain := []byte("ed25519-schnorr-test-domain")
	proof, public := testProof(t)
	response, err := edcurve.ScalarFromCanonical(proof.Response)
	if err != nil {
		t.Fatal(err)
	}
	response.Add(response, edcurve.ScalarOne())
	tamperedResponse := response.Bytes()
	response.Set(fed.NewScalar())

	tests := []struct {
		name   string
		public []byte
		proof  *Proof
	}{
		{name: "wrong public", public: testPublic(t, 17), proof: proof},
		{name: "wrong commitment", public: public, proof: &Proof{Commitment: testPublic(t, 19), Response: slices.Clone(proof.Response)}},
		{name: "wrong response", public: public, proof: &Proof{Commitment: slices.Clone(proof.Commitment), Response: tamperedResponse}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if Verify(domain, tc.public, tc.proof) {
				t.Fatal("tampered proof verified")
			}
		})
	}
}

func TestPreparationFinalizeConsumesNonceOnEveryTerminalPath(t *testing.T) {
	public := testPublic(t, 13)
	domain := []byte("final-domain")

	t.Run("success", func(t *testing.T) {
		preparation, err := Prepare(testutil.DeterministicReader(7302), public)
		if err != nil {
			t.Fatal(err)
		}
		nonce := preparation.nonce
		firstCommitment := preparation.Commitment()
		callerCopy := preparation.Commitment()
		callerCopy[0] ^= 1
		if !bytes.Equal(preparation.Commitment(), firstCommitment) {
			t.Fatal("Commitment returned an aliased slice")
		}

		proof, err := preparation.Finalize(domain, testSecretScalar(t, 13))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(proof.Commitment, firstCommitment) {
			t.Fatal("Finalize did not reuse the published commitment")
		}
		if !Verify(domain, public, proof) {
			t.Fatal("finalized proof did not verify")
		}
		if preparation.Commitment() != nil || nonce.FixedLen() != 0 {
			t.Fatal("successful Finalize retained the nonce")
		}
		if _, err := preparation.Finalize(domain, testSecretScalar(t, 13)); err == nil {
			t.Fatal("consumed preparation finalized twice")
		}
	})

	t.Run("failure", func(t *testing.T) {
		preparation, err := Prepare(testutil.DeterministicReader(7303), public)
		if err != nil {
			t.Fatal(err)
		}
		nonce := preparation.nonce
		if _, err := preparation.Finalize(domain, testSecretScalar(t, 17)); err == nil {
			t.Fatal("Finalize accepted a secret for another public key")
		}
		if preparation.Commitment() != nil || nonce.FixedLen() != 0 {
			t.Fatal("failed Finalize retained the nonce")
		}
	})

	t.Run("staged commit", func(t *testing.T) {
		preparation, err := Prepare(testutil.DeterministicReader(7304), public)
		if err != nil {
			t.Fatal(err)
		}
		nonce := preparation.nonce
		staged, err := preparation.PrepareFinalize(domain, testSecretScalar(t, 13))
		if err != nil {
			t.Fatal(err)
		}
		proof := staged.Proof()
		if proof == nil {
			t.Fatal("staged proof was unavailable")
		}
		mutated := staged.Proof()
		mutated.Response[0] ^= 1
		if bytes.Equal(mutated.Response, staged.Proof().Response) {
			t.Fatal("staged Proof returned an aliased value")
		}
		if _, err := preparation.PrepareFinalize(domain, testSecretScalar(t, 13)); err == nil {
			t.Fatal("preparation allowed two concurrent finalizations")
		}
		if err := staged.Commit(); err != nil {
			t.Fatal(err)
		}
		if preparation.Commitment() != nil || nonce.FixedLen() != 0 {
			t.Fatal("committed finalization retained the nonce")
		}
		if !Verify(domain, public, proof) {
			t.Fatal("committed staged proof did not verify")
		}
		if staged.Proof() != nil {
			t.Fatal("committed finalization retained its proof")
		}
		if err := staged.Commit(); err == nil {
			t.Fatal("finalization committed twice")
		}
	})

	t.Run("staged cancellation", func(t *testing.T) {
		preparation, err := Prepare(testutil.DeterministicReader(7305), public)
		if err != nil {
			t.Fatal(err)
		}
		nonce := preparation.nonce
		staged, err := preparation.PrepareFinalize(domain, testSecretScalar(t, 13))
		if err != nil {
			t.Fatal(err)
		}
		staged.Destroy()
		staged.Destroy()
		if preparation.Commitment() != nil || nonce.FixedLen() != 0 {
			t.Fatal("cancelled finalization retained the nonce")
		}
		if staged.Proof() != nil {
			t.Fatal("cancelled finalization retained its proof")
		}
		if _, err := preparation.PrepareFinalize(domain, testSecretScalar(t, 13)); err == nil {
			t.Fatal("cancelled preparation was reusable")
		}
	})

	t.Run("preparation cancellation", func(t *testing.T) {
		preparation, err := Prepare(testutil.DeterministicReader(7306), public)
		if err != nil {
			t.Fatal(err)
		}
		nonce := preparation.nonce
		preparation.Destroy()
		preparation.Destroy()
		if preparation.Commitment() != nil || nonce.FixedLen() != 0 {
			t.Fatal("destroyed preparation retained the nonce")
		}
	})
}

func TestPrepareRejectsInvalidPublicAndReaderFailure(t *testing.T) {
	t.Parallel()

	identity := fed.NewIdentityPoint().Bytes()
	torsion := make([]byte, testPointSize)
	torsionPoint, err := fed.NewIdentityPoint().SetBytes(torsion)
	if err != nil {
		t.Fatal(err)
	}
	mixed := fed.NewIdentityPoint().Add(fed.NewGeneratorPoint(), torsionPoint).Bytes()
	nonCanonicalIdentity := slices.Clone(identity)
	nonCanonicalIdentity[len(nonCanonicalIdentity)-1] |= 0x80

	for _, tc := range []struct {
		name   string
		public []byte
	}{
		{name: "nil", public: nil},
		{name: "identity", public: identity},
		{name: "torsion", public: torsion},
		{name: "torsion component", public: mixed},
		{name: "noncanonical", public: nonCanonicalIdentity},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if preparation, err := Prepare(testutil.DeterministicReader(7307), tc.public); err == nil || preparation != nil {
				t.Fatal("Prepare accepted an invalid public point")
			}
		})
	}

	readerErr := errors.New("reader failed")
	preparation, err := Prepare(errorReader{err: readerErr}, testPublic(t, 13))
	if !errors.Is(err, readerErr) || preparation != nil {
		t.Fatalf("Prepare reader failure = %v, want sentinel", err)
	}
}

func TestProveRejectsInvalidSecrets(t *testing.T) {
	t.Parallel()

	order := edcurve.Order()
	q := littleEndianScalar(new(big.Int).Set(order))
	qPlusOne := littleEndianScalar(new(big.Int).Add(new(big.Int).Set(order), big.NewInt(1)))
	tests := []struct {
		name   string
		secret *secret.Scalar
	}{
		{name: "nil", secret: nil},
		{name: "wrong width", secret: testSecretFromBytes(t, []byte{1}, edcurve.ScalarSize-1)},
		{name: "zero", secret: testSecretFromBytes(t, make([]byte, edcurve.ScalarSize), edcurve.ScalarSize)},
		{name: "q", secret: testSecretFromBytes(t, q, edcurve.ScalarSize)},
		{name: "q plus one", secret: testSecretFromBytes(t, qPlusOne, edcurve.ScalarSize)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			proof, public, err := ProveWithReader(testutil.DeterministicReader(7308), []byte("domain"), tc.secret)
			if err == nil || proof != nil || public != nil {
				t.Fatal("ProveWithReader accepted an invalid secret")
			}
		})
	}
}

func TestProofPointValidationRejectsIdentityTorsionAndNoncanonical(t *testing.T) {
	t.Parallel()

	validProof, public := testProof(t)
	identity := fed.NewIdentityPoint().Bytes()
	torsion := make([]byte, testPointSize)
	torsionPoint, err := fed.NewIdentityPoint().SetBytes(torsion)
	if err != nil {
		t.Fatal(err)
	}
	mixed := fed.NewIdentityPoint().Add(fed.NewGeneratorPoint(), torsionPoint).Bytes()
	nonCanonicalIdentity := slices.Clone(identity)
	nonCanonicalIdentity[len(nonCanonicalIdentity)-1] |= 0x80

	invalidPoints := []struct {
		name  string
		point []byte
	}{
		{name: "identity", point: identity},
		{name: "torsion", point: torsion},
		{name: "torsion component", point: mixed},
		{name: "noncanonical", point: nonCanonicalIdentity},
		{name: "wrong width", point: []byte{1}},
	}
	for _, tc := range invalidPoints {
		t.Run("commitment "+tc.name, func(t *testing.T) {
			t.Parallel()
			candidate := &Proof{Commitment: slices.Clone(tc.point), Response: make([]byte, edcurve.ScalarSize)}
			if err := candidate.Validate(); err == nil {
				t.Fatal("Validate accepted an invalid commitment")
			}
			if _, err := candidate.MarshalBinary(); err == nil {
				t.Fatal("MarshalBinary accepted an invalid commitment")
			}
			if Verify([]byte("ed25519-schnorr-test-domain"), public, candidate) {
				t.Fatal("Verify accepted an invalid commitment")
			}
		})
		t.Run("public "+tc.name, func(t *testing.T) {
			t.Parallel()
			if Verify([]byte("ed25519-schnorr-test-domain"), tc.point, validProof) {
				t.Fatal("Verify accepted an invalid public point")
			}
		})
	}
}

func TestProofResponseAllowsZeroAndRejectsNoncanonicalBoundaries(t *testing.T) {
	t.Parallel()

	commitment := testPublic(t, 29)
	order := edcurve.Order()
	qMinusOne := littleEndianScalar(new(big.Int).Sub(new(big.Int).Set(order), big.NewInt(1)))
	q := littleEndianScalar(new(big.Int).Set(order))
	qPlusOne := littleEndianScalar(new(big.Int).Add(new(big.Int).Set(order), big.NewInt(1)))

	for _, tc := range []struct {
		name     string
		response []byte
		accept   bool
	}{
		{name: "zero", response: make([]byte, edcurve.ScalarSize), accept: true},
		{name: "q minus one", response: qMinusOne, accept: true},
		{name: "q", response: q},
		{name: "q plus one", response: qPlusOne},
		{name: "short", response: make([]byte, edcurve.ScalarSize-1)},
		{name: "long", response: make([]byte, edcurve.ScalarSize+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			candidate := &Proof{Commitment: slices.Clone(commitment), Response: slices.Clone(tc.response)}
			validateErr := candidate.Validate()
			raw, marshalErr := candidate.MarshalBinary()
			if tc.accept {
				if validateErr != nil || marshalErr != nil {
					t.Fatalf("canonical response rejected: validate=%v marshal=%v", validateErr, marshalErr)
				}
				decoded, err := tss.DecodeBinary[Proof](raw)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(decoded.Response, tc.response) {
					t.Fatal("response changed during canonical round trip")
				}
				return
			}
			if validateErr == nil || marshalErr == nil {
				t.Fatal("noncanonical response was accepted")
			}

			raw, err := wire.MarshalFields(proofWireVersion, proofWireType, []wire.Field{
				{Tag: 1, Value: slices.Clone(commitment)},
				{Tag: 2, Value: slices.Clone(tc.response)},
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tss.DecodeBinary[Proof](raw); err == nil {
				t.Fatal("decoder accepted a noncanonical response")
			}
		})
	}
}

func TestProofDecoderRejectsWrongShapeAndIsFailAtomic(t *testing.T) {
	t.Parallel()

	proof, _ := testProof(t)
	validRaw, err := proof.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		wireType string
		version  uint16
		fields   []wire.Field
	}{
		{name: "wrong type", wireType: proofWireType + ".wrong", version: proofWireVersion, fields: []wire.Field{
			{Tag: 1, Value: proof.Commitment}, {Tag: 2, Value: proof.Response},
		}},
		{name: "wrong version", wireType: proofWireType, version: proofWireVersion + 1, fields: []wire.Field{
			{Tag: 1, Value: proof.Commitment}, {Tag: 2, Value: proof.Response},
		}},
		{name: "missing commitment", wireType: proofWireType, version: proofWireVersion, fields: []wire.Field{
			{Tag: 2, Value: proof.Response},
		}},
		{name: "missing response", wireType: proofWireType, version: proofWireVersion, fields: []wire.Field{
			{Tag: 1, Value: proof.Commitment},
		}},
		{name: "unknown field", wireType: proofWireType, version: proofWireVersion, fields: []wire.Field{
			{Tag: 1, Value: proof.Commitment}, {Tag: 2, Value: proof.Response}, {Tag: 3, Value: []byte{1}},
		}},
		{name: "oversized commitment", wireType: proofWireType, version: proofWireVersion, fields: []wire.Field{
			{Tag: 1, Value: make([]byte, testPointSize+1)}, {Tag: 2, Value: proof.Response},
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			raw, err := wire.MarshalFields(tc.version, tc.wireType, tc.fields)
			if err != nil {
				t.Fatal(err)
			}
			original := proof.Clone()
			receiver := proof.Clone()
			if err := receiver.UnmarshalBinary(raw); err == nil {
				t.Fatal("malformed proof decoded")
			}
			if !bytes.Equal(receiver.Commitment, original.Commitment) || !bytes.Equal(receiver.Response, original.Response) {
				t.Fatal("failed decode mutated the receiver")
			}
		})
	}

	var nilProof *Proof
	if err := nilProof.UnmarshalBinary(validRaw); err == nil {
		t.Fatal("nil proof receiver decoded")
	}
	if _, err := nilProof.MarshalWireValue(); err == nil {
		t.Fatal("nil proof marshaled as a custom wire value")
	}
}

type errorReader struct {
	err error
}

func (r errorReader) Read([]byte) (int, error) {
	return 0, r.err
}

var _ io.Reader = errorReader{}

type proofContainer struct {
	Proof *Proof `wire:"1,record"`
}

func (proofContainer) WireType() string { return "zk.schnorr-ed25519.test-container" }

func (proofContainer) WireVersion() uint16 { return 1 }
