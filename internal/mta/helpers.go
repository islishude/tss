package mta

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/wire"
)

const messageVersion = 1

func randomScalar(reader io.Reader) (*big.Int, error) {
	for {
		x, err := rand.Int(reader, secp.Order())
		if err != nil {
			return nil, err
		}
		if x.Sign() != 0 {
			return x, nil
		}
	}
}

func requireExactMessageTags(fields []wire.Field, tags ...uint16) error {
	if len(fields) != len(tags) {
		return fmt.Errorf("got %d fields, want %d", len(fields), len(tags))
	}
	for i, tag := range tags {
		if fields[i].Tag != tag {
			return fmt.Errorf("unexpected field tag %d at index %d", fields[i].Tag, i)
		}
	}
	return nil
}

func mustMessageField(fields []wire.Field, tag uint16) []byte {
	value, _ := wire.Require(fields, tag)
	return value
}

func validatePositiveIntegerBytes(in []byte) error {
	if len(in) == 0 {
		return errors.New("empty integer")
	}
	if in[0] == 0 {
		return errors.New("non-minimal integer encoding")
	}
	if new(big.Int).SetBytes(in).Sign() <= 0 {
		return errors.New("integer must be positive")
	}
	return nil
}

// scalarFixedBytes encodes a secp256k1 scalar as fixed-length 32-byte big-endian.
func scalarFixedBytes(x *big.Int) []byte {
	const scalarByteLen = 32
	b := x.Bytes()
	if len(b) >= scalarByteLen {
		return b[len(b)-scalarByteLen:]
	}
	out := make([]byte, scalarByteLen)
	copy(out[scalarByteLen-len(b):], b)
	return out
}
