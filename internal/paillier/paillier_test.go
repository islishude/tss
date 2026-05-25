package paillier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	"github.com/islishude/tss/internal/wire"
)

func TestEncryptDecryptAndHomomorphicOps(t *testing.T) {
	restore := SetMinimumModulusBitsForTesting(512)
	defer restore()
	sk, err := GenerateKey(nil, 512)
	if err != nil {
		t.Fatal(err)
	}
	pk := sk.PublicKey
	c1, _, err := pk.Encrypt(nil, big.NewInt(12))
	if err != nil {
		t.Fatal(err)
	}
	c2, _, err := pk.Encrypt(nil, big.NewInt(30))
	if err != nil {
		t.Fatal(err)
	}
	sum, err := pk.AddCiphertexts(c1, c2)
	if err != nil {
		t.Fatal(err)
	}
	got, err := sk.Decrypt(sum)
	if err != nil {
		t.Fatal(err)
	}
	if got.Cmp(big.NewInt(42)) != 0 {
		t.Fatalf("sum = %s, want 42", got)
	}
	scaled, err := pk.MulPlaintext(c1, big.NewInt(3))
	if err != nil {
		t.Fatal(err)
	}
	got, err = sk.Decrypt(scaled)
	if err != nil {
		t.Fatal(err)
	}
	if got.Cmp(big.NewInt(36)) != 0 {
		t.Fatalf("scaled = %s, want 36", got)
	}
}

func TestMarshalRoundTrip(t *testing.T) {
	restore := SetMinimumModulusBitsForTesting(512)
	defer restore()
	sk, err := GenerateKey(nil, 512)
	if err != nil {
		t.Fatal(err)
	}
	pubRaw, err := sk.PublicKey.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	pubRaw2, err := sk.PublicKey.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pubRaw, pubRaw2) {
		t.Fatal("public key encoding is not deterministic")
	}
	pub, err := UnmarshalPublicKey(pubRaw)
	if err != nil {
		t.Fatal(err)
	}
	if pub.N.Cmp(sk.N) != 0 || pub.G.Cmp(sk.G) != 0 {
		t.Fatal("public key mismatch after round trip")
	}
	privRaw, err := sk.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	privRaw2, err := sk.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(privRaw, privRaw2) {
		t.Fatal("private key encoding is not deterministic")
	}
	priv, err := UnmarshalPrivateKey(privRaw)
	if err != nil {
		t.Fatal(err)
	}
	if priv.N.Cmp(sk.N) != 0 || priv.Lambda.Cmp(sk.Lambda) != 0 {
		t.Fatal("private key mismatch after round trip")
	}
}

func TestPrivateKeyJSONAndDestroy(t *testing.T) {
	restore := SetMinimumModulusBitsForTesting(512)
	defer restore()
	sk, err := GenerateKey(nil, 512)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := json.Marshal(sk); err == nil {
		t.Fatal("pointer private key JSON encoded")
	}
	if _, err := json.Marshal(*sk); err == nil {
		t.Fatal("value private key JSON encoded")
	}
	n := new(big.Int).Set(sk.N)
	sk.Destroy()
	for name, value := range map[string]*big.Int{
		"lambda": sk.Lambda,
		"mu":     sk.Mu,
		"p":      sk.P,
		"q":      sk.Q,
	} {
		if value == nil || value.Sign() != 0 {
			t.Fatalf("%s was not cleared", name)
		}
	}
	if sk.N.Cmp(n) != 0 {
		t.Fatal("public modulus changed")
	}
}

func TestRejectsNonCanonicalPublicKey(t *testing.T) {
	restore := SetMinimumModulusBitsForTesting(512)
	defer restore()
	sk, err := GenerateKey(nil, 512)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := sk.PublicKey.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	nonCanonical := append([]byte(" "), raw...)
	if _, err := UnmarshalPublicKey(nonCanonical); err == nil {
		t.Fatal("expected non-canonical public key rejection")
	}
	if _, err := UnmarshalPublicKey([]byte(`{"n":"01","g":"02"}`)); err == nil {
		t.Fatal("expected JSON public key rejection")
	}
	if _, err := UnmarshalPrivateKey([]byte(`{"public_key":{"n":"01","g":"02"}}`)); err == nil {
		t.Fatal("expected JSON private key rejection")
	}
	withLeadingZero, err := rewritePaillierField(raw, publicKeyWireType, publicKeyFieldN, append([]byte{0}, sk.N.Bytes()...))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalPublicKey(withLeadingZero); err == nil {
		t.Fatal("expected non-minimal public modulus rejection")
	}
	privRaw, err := sk.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	badPrivate, err := rewritePaillierField(privRaw, privateKeyWireType, privateKeyFieldP, append([]byte{0}, sk.P.Bytes()...))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalPrivateKey(badPrivate); err == nil {
		t.Fatal("expected non-minimal private factor rejection")
	}
	wrongType, err := wire.Marshal(paillierWireVersion, "wrong.paillier.public-key", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalPublicKey(wrongType); err == nil {
		t.Fatal("expected wrong public key type rejection")
	}
}

func TestValidateCiphertextGroup(t *testing.T) {
	restore := SetMinimumModulusBitsForTesting(512)
	defer restore()
	sk, err := GenerateKey(nil, 512)
	if err != nil {
		t.Fatal(err)
	}
	if err := sk.ValidateCiphertext(big.NewInt(0)); err == nil {
		t.Fatal("expected zero ciphertext rejection")
	}
	if err := sk.ValidateCiphertext(sk.NSquared); err == nil {
		t.Fatal("expected n^2 ciphertext rejection")
	}
	if err := sk.ValidateCiphertext(new(big.Int).Set(sk.N)); err == nil {
		t.Fatal("expected non-invertible ciphertext rejection")
	}
}

func FuzzPublicKeyUnmarshal(f *testing.F) {
	restore := SetMinimumModulusBitsForTesting(512)
	defer restore()
	sk, err := GenerateKey(nil, 512)
	if err != nil {
		f.Fatal(err)
	}
	raw, err := sk.PublicKey.MarshalBinary()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"n":"01","g":"02"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = UnmarshalPublicKey(data)
	})
}

func FuzzPrivateKeyUnmarshal(f *testing.F) {
	restore := SetMinimumModulusBitsForTesting(512)
	defer restore()
	sk, err := GenerateKey(nil, 512)
	if err != nil {
		f.Fatal(err)
	}
	raw, err := sk.MarshalBinary()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"public_key":{"n":"01","g":"02"}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = UnmarshalPrivateKey(data)
	})
}

func rewritePaillierField(raw []byte, typeID string, tag uint16, value []byte) ([]byte, error) {
	version, fields, err := wire.Unmarshal(raw, typeID)
	if err != nil {
		return nil, err
	}
	for i := range fields {
		if fields[i].Tag == tag {
			fields[i].Value = make([]byte, len(value))
			copy(fields[i].Value, value)
			return wire.Marshal(version, typeID, fields)
		}
	}
	return nil, fmt.Errorf("missing Paillier field %d", tag)
}
