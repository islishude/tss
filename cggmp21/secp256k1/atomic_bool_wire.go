package secp256k1

import (
	"errors"
	"sync/atomic"

	"github.com/islishude/tss/internal/wire"
)

// AtomicBoolWire wraps an atomic.Bool for canonical wire value encoding.
type AtomicBoolWire struct {
	*atomic.Bool
}

// NewAtomicBoolWire returns an AtomicBoolWire initialized to v.
func NewAtomicBoolWire(v bool) AtomicBoolWire {
	b := new(atomic.Bool)
	b.Store(v)
	return AtomicBoolWire{Bool: b}
}

// MarshalWireValue encodes b as a single canonical bool byte.
func (b AtomicBoolWire) MarshalWireValue() ([]byte, error) {
	if b.Bool == nil {
		return nil, errors.New("nil atomic bool")
	}
	return wire.Bool(b.Load()), nil
}

// UnmarshalWireValue decodes a single canonical bool byte into b.
func (b *AtomicBoolWire) UnmarshalWireValue(in []byte) error {
	if b == nil {
		return errors.New("nil atomic bool wire")
	}
	value, err := wire.DecodeBool(in)
	if err != nil {
		return err
	}
	b.Bool = new(atomic.Bool)
	b.Store(value)
	return nil
}
