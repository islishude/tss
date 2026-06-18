package paillier

import (
	"context"
	"encoding/json"
	"io"
	"math/big"
	"testing"

	"github.com/islishude/tss/internal/secret"
)

func TestPrivateKeyJSONAndDestroy(t *testing.T) {
	t.Parallel()

	sk, err := GenerateKeyForTest(context.Background(), nil, 512)
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
	for _, b := range sk.Lambda.FixedBytes() {
		if b != 0 {
			t.Fatal("lambda was not cleared")
		}
	}
	for _, b := range sk.Mu.FixedBytes() {
		if b != 0 {
			t.Fatal("mu was not cleared")
		}
	}
	for name, value := range map[string]*secret.Scalar{
		"p": sk.P,
		"q": sk.Q,
	} {
		if value == nil || value.FixedLen() != 0 {
			t.Fatalf("%s was not cleared", name)
		}
	}
	if sk.N.Cmp(n) != 0 {
		t.Fatal("public modulus changed")
	}
}

type nonComparableReader struct {
	buf    []byte
	source io.Reader
}

func (r nonComparableReader) Read(p []byte) (int, error) {
	return r.source.Read(p)
}
