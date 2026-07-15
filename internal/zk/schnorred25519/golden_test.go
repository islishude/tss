package schnorred25519

import (
	"bytes"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testvectors"
)

func TestGoldenEd25519SchnorrProof(t *testing.T) {
	t.Parallel()

	proof, _ := testProof(t)
	raw, err := proof.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	testvectors.CheckHexGolden(t, "wire/v1/zk/Ed25519SchnorrProof.golden", raw)

	decoded, err := tss.DecodeBinary[Proof](raw)
	if err != nil {
		t.Fatal(err)
	}
	reencoded, err := decoded.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, reencoded) {
		t.Fatal("Ed25519 Schnorr proof changed across canonical round trip")
	}
	if _, err := tss.DecodeBinary[Proof](append(bytes.Clone(raw), 0)); err == nil {
		t.Fatal("Ed25519 Schnorr proof accepted trailing data")
	}
}
