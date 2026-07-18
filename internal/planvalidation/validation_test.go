package planvalidation

import (
	"bytes"
	"errors"
	"testing"

	"github.com/islishude/tss"
)

func TestRequireHash(t *testing.T) {
	want := bytes.Repeat([]byte{0x42}, 32)

	if err := RequireHash("sign", want, want); err != nil {
		t.Fatalf("RequireHash(equal) = %v", err)
	}
	if err := RequireHash("sign", want[:31], want); err == nil || err.Error() != "sign plan hash must be 32 bytes" {
		t.Fatalf("RequireHash(short) = %v, want exact size error", err)
	}
	got := bytes.Clone(want)
	got[0] ^= 0xff
	if err := RequireHash("sign", got, want); err == nil || !errors.Is(err, tss.ErrPlanHashMismatch) || err.Error() != "sign: lifecycle plan hash mismatch" {
		t.Fatalf("RequireHash(mismatch) = %v, want wrapped plan mismatch", err)
	}
}

func TestInvalidConfig(t *testing.T) {
	cause := errors.New("bad plan")
	err := InvalidConfig(7, cause)
	var protocolErr *tss.ProtocolError
	if !errors.As(err, &protocolErr) {
		t.Fatalf("InvalidConfig() = %T, want *tss.ProtocolError", err)
	}
	if protocolErr.Code != tss.ErrCodeInvalidConfig || protocolErr.Round != 0 || protocolErr.Party != 7 || !errors.Is(err, cause) {
		t.Fatalf("InvalidConfig() = %#v, want invalid-config wrapper", protocolErr)
	}
	if got := InvalidConfig(9, err); !errors.Is(got, err) {
		t.Fatalf("InvalidConfig(existing) did not preserve the existing error")
	}
	if got := InvalidConfig(1, nil); got != nil {
		t.Fatalf("InvalidConfig(nil) = %v, want nil", got)
	}
}
