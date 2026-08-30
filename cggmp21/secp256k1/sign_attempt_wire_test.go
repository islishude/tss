package secp256k1

import (
	"bytes"
	"errors"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
)

func TestSignAttemptCompletionRejectsTrailingBytes(t *testing.T) {
	t.Parallel()

	signature := Signature{
		R:          secp.ScalarFromUint64(1).Bytes(),
		S:          secp.ScalarFromUint64(2).Bytes(),
		RecoveryID: 1,
	}
	raw, err := marshalSignAttemptCompletion(bytes.Repeat([]byte{0xa5}, 32), signature, testLimits())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unmarshalSignAttemptCompletion(raw, testLimits()); err != nil {
		t.Fatalf("canonical completion rejected: %v", err)
	}
	if _, err := unmarshalSignAttemptCompletion(append(bytes.Clone(raw), 0), testLimits()); !errors.Is(err, ErrSignAttemptCorrupt) {
		t.Fatalf("trailing completion error = %v, want ErrSignAttemptCorrupt", err)
	}
}
