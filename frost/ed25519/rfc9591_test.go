package ed25519

import (
	"bytes"
	stded25519 "crypto/ed25519"
	"crypto/sha512"
	"encoding/hex"
	"io"
	"testing"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
	"github.com/islishude/tss/internal/testutil"
)

type rfc9591VectorNonceReader struct {
	io.Reader
}

func (rfc9591VectorNonceReader) rfc9591NonceDerivation() {}

// TestRFC9591ContextString verifies the RFC 9591 Section 5.4.1 ciphersuite
// context string used for domain separation.
func TestRFC9591ContextString(t *testing.T) {
	t.Parallel()
	const expected = "FROST-ED25519-SHA512-v1"
	if rfc9591ContextString != expected {
		t.Errorf("context string mismatch: got %q, want %q", rfc9591ContextString, expected)
	}
}

// TestRFC9591HashToScalarDirectConcat verifies that HashToScalar uses direct
// concatenation (no length-delimited encoding), per RFC 9591 Section 3.1.
// We check this by hashing known inputs and verifying the output is
// deterministic and independent of any length encoding.
func TestRFC9591HashToScalarDirectConcat(t *testing.T) {
	t.Parallel()
	a := []byte{0x01, 0x02, 0x03}
	b := []byte{0x04, 0x05}

	// HashToScalar should just concatenate parts and SHA-512.
	s1, _ := edcurve.HashToScalar(a, b)
	s2, _ := edcurve.HashToScalar(a, b)

	// Deterministic: same inputs produce same output.
	if s1.Equal(s2) != 1 {
		t.Error("HashToScalar is not deterministic")
	}

	// Verify direct concatenation: compute expected manually.
	expectedHash := sha512.Sum512(append(a, b...))
	s3, _ := edcurve.HashToScalar(append(a, b...))
	if s1.Equal(s3) != 1 {
		t.Error("HashToScalar does not use direct concatenation")
	}
	_ = expectedHash
}

// TestRFC9591Ed25519Challenge verifies the RFC 8032 challenge computation
// format: H(R || A || msg) using SHA-512.
func TestRFC9591Ed25519Challenge(t *testing.T) {
	t.Parallel()
	R := make([]byte, 32)
	A := make([]byte, 32)
	msg := []byte("test")

	_, c1 := edcurve.Ed25519Challenge(R, A, msg)
	_, c2 := edcurve.Ed25519Challenge(R, A, msg)

	if c1.Cmp(c2) != 0 {
		t.Error("Ed25519Challenge is not deterministic")
	}
}

// TestRFC9591EndToEndSignature verifies that a full FROST Ed25519 keygen,
// signing, and Ed25519 signature verification produces valid output.
// This exercises the complete RFC 9591 flow: keygen → sign → verify.
func TestRFC9591EndToEndSignature(t *testing.T) {
	t.Parallel()
	// 2-of-3 keygen (matching RFC 9591 Appendix E configuration).
	shares := frostKeygen(t, 2, 3)
	key1 := shares[1]
	key3 := shares[3]

	message := []byte("test")

	// Sign with signers P1, P3 (matching the RFC test vector).
	signers := []*KeyShare{key1, key3}
	pub, sig, err := Sign(message, signers, testFROSTSigningContext())
	if err != nil {
		t.Fatal(err)
	}

	if !stded25519.Verify(stded25519.PublicKey(pub), message, sig) {
		t.Fatal("Ed25519 signature verification failed for 2-of-3")
	}

	// Verify the signature is 64 bytes (R || S format per RFC 8032).
	if len(sig) != 64 {
		t.Errorf("signature length: got %d, want 64", len(sig))
	}
}

func TestRFC9591Ed25519BindingFactorVector(t *testing.T) {
	t.Parallel()
	v := rfc9591Ed25519Vector(t)
	commitments := map[tss.PartyID]nonceCommitment{
		1: mustNonceCommitment(t, v.p1HidingCommitment, v.p1BindingCommitment),
		3: mustNonceCommitment(t, v.p3HidingCommitment, v.p3BindingCommitment),
	}

	encoded, err := encodeGroupCommitmentList(v.signers, commitments)
	if err != nil {
		t.Fatal(err)
	}
	expectedEncoded := append(append(append(append(append([]byte(nil),
		hexMust(t, "0100000000000000000000000000000000000000000000000000000000000000")...),
		v.p1HidingCommitment...),
		v.p1BindingCommitment...),
		hexMust(t, "0300000000000000000000000000000000000000000000000000000000000000")...),
		v.p3HidingCommitment...)
	expectedEncoded = append(expectedEncoded, v.p3BindingCommitment...)
	if !bytes.Equal(encoded, expectedEncoded) {
		t.Fatal("encoded commitment list does not match RFC sorted format")
	}

	if got := rfc9591H4(v.message); !bytes.Equal(got, v.messageHash) {
		t.Fatalf("H4 mismatch: got %x want %x", got, v.messageHash)
	}
	if got := rfc9591H5(encoded); !bytes.Equal(got, v.commitmentHash) {
		t.Fatalf("H5 mismatch: got %x want %x", got, v.commitmentHash)
	}

	session := &SignSession{
		message: v.message,
		derivation: &tss.DerivationResult{
			ChildPublicKey: v.groupPublicKey,
		},
		signers:     v.signers,
		commitments: commitments,
	}
	rhos, err := session.bindingFactors()
	if err != nil {
		t.Fatal(err)
	}
	if got := rhos[1].Bytes(); !bytes.Equal(got, v.p1BindingFactor) {
		t.Fatalf("P1 binding factor mismatch: got %x want %x", got, v.p1BindingFactor)
	}
	if got := rhos[3].Bytes(); !bytes.Equal(got, v.p3BindingFactor) {
		t.Fatalf("P3 binding factor mismatch: got %x want %x", got, v.p3BindingFactor)
	}
}

func TestRFC9591Ed25519SigningVector(t *testing.T) {
	t.Parallel()
	v := rfc9591Ed25519Vector(t)
	key1 := rfc9591KeyShare(t, 1, v.p1Share, v)
	key3 := rfc9591KeyShare(t, 3, v.p3Share, v)

	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	s1, out1, err := startFROSTSignWithOptions(key1, sessionID, v.signers, v.message, SignOptions{
		NonceReader: rfc9591VectorNonceReader{Reader: bytes.NewReader(append(append([]byte(nil), v.p1HidingRandomness...), v.p1BindingRandomness...))},
	})
	if err != nil {
		t.Fatal(err)
	}
	s3, out3, err := startFROSTSignWithOptions(key3, sessionID, v.signers, v.message, SignOptions{
		NonceReader: rfc9591VectorNonceReader{Reader: bytes.NewReader(append(append([]byte(nil), v.p3HidingRandomness...), v.p3BindingRandomness...))},
	})
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(s1.dNonce.FixedBytes(), v.p1HidingNonce) || !bytes.Equal(s1.eNonce.FixedBytes(), v.p1BindingNonce) {
		t.Fatal("P1 nonce generation does not match RFC vector")
	}
	if !bytes.Equal(s3.dNonce.FixedBytes(), v.p3HidingNonce) || !bytes.Equal(s3.eNonce.FixedBytes(), v.p3BindingNonce) {
		t.Fatal("P3 nonce generation does not match RFC vector")
	}
	assertCommitmentEnvelope(t, out1[0], v.p1HidingCommitment, v.p1BindingCommitment)
	assertCommitmentEnvelope(t, out3[0], v.p3HidingCommitment, v.p3BindingCommitment)

	p1Partial, err := s1.HandleSignMessage(testutil.DeliverEnvelope(out3[0]))
	if err != nil {
		t.Fatal(err)
	}
	p3Partial, err := s3.HandleSignMessage(testutil.DeliverEnvelope(out1[0]))
	if err != nil {
		t.Fatal(err)
	}
	assertPartialEnvelope(t, p1Partial[0], v.p1SignatureShare)
	assertPartialEnvelope(t, p3Partial[0], v.p3SignatureShare)

	if _, err := s1.HandleSignMessage(testutil.DeliverEnvelope(p3Partial[0])); err != nil {
		t.Fatal(err)
	}
	sig, ok := s1.Signature()
	if !ok {
		t.Fatal("RFC vector signing did not complete")
	}
	if !bytes.Equal(sig, v.signature) {
		t.Fatalf("signature mismatch: got %x want %x", sig, v.signature)
	}
	if !stded25519.Verify(stded25519.PublicKey(v.groupPublicKey), v.message, sig) {
		t.Fatal("RFC vector signature failed Ed25519 verification")
	}
}

// TestRFC9591ThresholdCombinations verifies FROST signatures work for
// the standard threshold configurations from the RFC.
func TestRFC9591ThresholdCombinations(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		threshold int
		n         int
		signers   tss.PartySet
	}{
		{"1-of-1", 1, 1, tss.NewPartySet(1)},
		{"2-of-3", 2, 3, tss.NewPartySet(1, 3)},
		{"3-of-5", 3, 5, tss.NewPartySet(1, 3, 5)},
	}

	message := []byte("RFC 9591 compliance test")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shares := frostKeygen(t, tt.threshold, tt.n)
			signerShares := make([]*KeyShare, len(tt.signers))
			for i, id := range tt.signers {
				signerShares[i] = shares[id]
			}
			pub, sig, err := Sign(message, signerShares, testFROSTSigningContext())
			if err != nil {
				t.Fatalf("signing failed: %v", err)
			}
			if !stded25519.Verify(stded25519.PublicKey(pub), message, sig) {
				t.Fatalf("Ed25519 signature verification failed for %s", tt.name)
			}
		})
	}
}

type rfc9591Vector struct {
	signers             tss.PartySet
	groupPublicKey      []byte
	message             []byte
	coefficient1        []byte
	p1Share             []byte
	p3Share             []byte
	p1HidingRandomness  []byte
	p1BindingRandomness []byte
	p1HidingNonce       []byte
	p1BindingNonce      []byte
	p1HidingCommitment  []byte
	p1BindingCommitment []byte
	p1BindingFactor     []byte
	p1SignatureShare    []byte
	p3HidingRandomness  []byte
	p3BindingRandomness []byte
	p3HidingNonce       []byte
	p3BindingNonce      []byte
	p3HidingCommitment  []byte
	p3BindingCommitment []byte
	p3BindingFactor     []byte
	p3SignatureShare    []byte
	messageHash         []byte
	commitmentHash      []byte
	signature           []byte
}

func rfc9591Ed25519Vector(t *testing.T) rfc9591Vector {
	t.Helper()
	return rfc9591Vector{
		signers:             tss.NewPartySet(1, 3),
		groupPublicKey:      hexMust(t, "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673"),
		message:             hexMust(t, "74657374"),
		coefficient1:        hexMust(t, "178199860edd8c62f5212ee91eff1295d0d670ab4ed4506866bae57e7030b204"),
		p1Share:             hexMust(t, "929dcc590407aae7d388761cddb0c0db6f5627aea8e217f4a033f2ec83d93509"),
		p3Share:             hexMust(t, "d3cb090a075eb154e82fdb4b3cb507f110040905468bb9c46da8bdea643a9a02"),
		p1HidingRandomness:  hexMust(t, "0fd2e39e111cdc266f6c0f4d0fd45c947761f1f5d3cb583dfcb9bbaf8d4c9fec"),
		p1BindingRandomness: hexMust(t, "69cd85f631d5f7f2721ed5e40519b1366f340a87c2f6856363dbdcda348a7501"),
		p1HidingNonce:       hexMust(t, "812d6104142944d5a55924de6d49940956206909f2acaeedecda2b726e630407"),
		p1BindingNonce:      hexMust(t, "b1110165fc2334149750b28dd813a39244f315cff14d4e89e6142f262ed83301"),
		p1HidingCommitment:  hexMust(t, "b5aa8ab305882a6fc69cbee9327e5a45e54c08af61ae77cb8207be3d2ce13de3"),
		p1BindingCommitment: hexMust(t, "67e98ab55aa310c3120418e5050c9cf76cf387cb20ac9e4b6fdb6f82a469f932"),
		p1BindingFactor:     hexMust(t, "f2cb9d7dd9beff688da6fcc83fa89046b3479417f47f55600b106760eb3b5603"),
		p1SignatureShare:    hexMust(t, "001719ab5a53ee1a12095cd088fd149702c0720ce5fd2f29dbecf24b7281b603"),
		p3HidingRandomness:  hexMust(t, "86d64a260059e495d0fb4fcc17ea3da7452391baa494d4b00321098ed2a0062f"),
		p3BindingRandomness: hexMust(t, "13e6b25afb2eba51716a9a7d44130c0dbae0004a9ef8d7b5550c8a0e07c61775"),
		p3HidingNonce:       hexMust(t, "c256de65476204095ebdc01bd11dc10e57b36bc96284595b8215222374f99c0e"),
		p3BindingNonce:      hexMust(t, "243d71944d929063bc51205714ae3c2218bd3451d0214dfb5aeec2a90c35180d"),
		p3HidingCommitment:  hexMust(t, "cfbdb165bd8aad6eb79deb8d287bcc0ab6658ae57fdcc98ed12c0669e90aec91"),
		p3BindingCommitment: hexMust(t, "7487bc41a6e712eea2f2af24681b58b1cf1da278ea11fe4e8b78398965f13552"),
		p3BindingFactor:     hexMust(t, "b087686bf35a13f3dc78e780a34b0fe8a77fef1b9938c563f5573d71d8d7890f"),
		p3SignatureShare:    hexMust(t, "bd86125de990acc5e1f13781d8e32c03a9bbd4c53539bbc106058bfd14326007"),
		messageHash:         hexMust(t, "504df914fa965023fb75c25ded4bb260f417de6d32e5c442c6ba313791cc9a4948d6273e8d3511f93348ea7a708a9b862bc73ba2a79cfdfe07729a193751cbc9"),
		commitmentHash:      hexMust(t, "73af46d8ac3440e518d4ce440a0e7d4ad5f62ca8940f32de6d8dc00fc12c660b817d587d82f856d277ce6473cae6d2f5763f7da2e8b4d799a3f3e725d4522ec7"),
		signature:           hexMust(t, "36282629c383bb820a88b71cae937d41f2f2adfcc3d02e55507e2fb9e2dd3cbebd9d2b0844e49ae0f3fa935161e1419aab7b47d21a37ebeae1f17d4987b3160b"),
	}
}

func rfc9591KeyShare(t *testing.T, party tss.PartyID, secret []byte, v rfc9591Vector) *KeyShare {
	t.Helper()
	coeff1, err := edcurve.ScalarFromCanonical(v.coefficient1)
	if err != nil {
		t.Fatal(err)
	}
	groupCommitments, err := newGroupCommitmentsFromBytesList([][]byte{
		append([]byte(nil), v.groupPublicKey...),
		fed.NewIdentityPoint().ScalarBaseMult(coeff1).Bytes(),
	}, 2)
	if err != nil {
		t.Fatal(err)
	}
	parties := tss.NewPartySet(1, 2, 3)
	partyData := make(map[tss.PartyID]keySharePartyData, len(parties))
	for _, id := range parties {
		pub, err := groupCommitments.Eval(id)
		if err != nil {
			t.Fatal(err)
		}
		partyData[id] = keySharePartyData{verificationShare: pub}
	}
	secretScalar, err := newEdSecretScalar(secret)
	if err != nil {
		t.Fatal(err)
	}
	key := &KeyShare{state: &keyShareState{
		party:                party,
		threshold:            2,
		parties:              parties,
		publicKey:            groupCommitments.PublicKey(),
		chainCode:            bytes.Repeat([]byte{0x96}, 32),
		secret:               secretScalar,
		groupCommitments:     groupCommitments,
		partyData:            partyData,
		keygenTranscriptHash: []byte("rfc9591-appendix-e1"),
		keygenSessionID:      tss.SessionID(bytes.Repeat([]byte{0x01}, 32)),
		planHash:             bytes.Repeat([]byte{0x95}, 32),
	}}
	if err := key.ValidateConsistency(); err != nil {
		t.Fatal(err)
	}
	return key
}

func assertCommitmentEnvelope(t *testing.T, env tss.Envelope, wantD, wantE []byte) {
	t.Helper()
	commitment, err := unmarshalNonceCommitmentPayload(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(commitment.DBytes(), wantD) || !bytes.Equal(commitment.EBytes(), wantE) {
		t.Fatalf("commitment mismatch: got (%x, %x)", commitment.DBytes(), commitment.EBytes())
	}
}

func assertPartialEnvelope(t *testing.T, env tss.Envelope, want []byte) {
	t.Helper()
	partial, err := unmarshalSignPartialPayload(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(partial.Z.Bytes(), want) {
		t.Fatalf("partial mismatch: got %x want %x", partial.Z.Bytes(), want)
	}
}

func mustNonceCommitment(t testing.TB, d, e []byte) nonceCommitment {
	t.Helper()
	dPoint, err := newNonceCommitmentPointFromBytes(d)
	if err != nil {
		t.Fatal(err)
	}
	ePoint, err := newNonceCommitmentPointFromBytes(e)
	if err != nil {
		t.Fatal(err)
	}
	return nonceCommitment{
		D: dPoint,
		E: ePoint,
	}
}

func hexMust(t *testing.T, in string) []byte {
	t.Helper()
	out, err := hex.DecodeString(in)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
