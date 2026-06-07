package paillier

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/islishude/tss/internal/wire"
)

func TestMarshalRoundTrip(t *testing.T) {
	sk, err := GenerateKey(context.Background(), nil, 512)
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
	if priv.N.Cmp(sk.N) != 0 || !priv.Lambda.Equal(sk.Lambda) || !priv.Mu.Equal(sk.Mu) {
		t.Fatal("private key mismatch after round trip")
	}
}

func TestRejectsNonCanonicalPublicKey(t *testing.T) {
	sk, err := GenerateKey(context.Background(), nil, 512)
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

func FuzzPublicKeyUnmarshal(f *testing.F) {
	sk, err := GenerateKey(context.Background(), nil, 512)
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
		pk, err := UnmarshalPublicKey(data)
		if err != nil {
			return
		}
		assertPayloadRemarshals(t, pk, (*PublicKey).MarshalBinary, UnmarshalPublicKey)
	})
}

func FuzzPrivateKeyUnmarshal(f *testing.F) {
	sk, err := GenerateKey(context.Background(), nil, 512)
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
		sk, err := UnmarshalPrivateKey(data)
		if err != nil {
			return
		}
		assertPayloadRemarshals(t, sk, (*PrivateKey).MarshalBinary, UnmarshalPrivateKey)
	})
}

func assertPayloadRemarshals[P any](t *testing.T, p P, marshal func(P) ([]byte, error), unmarshal func([]byte) (P, error)) {
	t.Helper()
	raw, err := marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := unmarshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, again) {
		t.Fatal("payload did not remarshal deterministically")
	}
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
