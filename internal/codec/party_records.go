package codec

import (
	"fmt"

	"github.com/islishude/tss/internal/wire"
)

// PartyBytes is a party-scoped byte string record.
type PartyBytes[T uint32Value] struct {
	Party T
	Bytes []byte
}

// PartyBytePair is a party-scoped pair of byte string records.
type PartyBytePair[T uint32Value] struct {
	Party  T
	First  []byte
	Second []byte
}

// EncodePartyBytes encodes party-scoped byte string records.
func EncodePartyBytes[T uint32Value](records []PartyBytes[T]) []byte {
	out := Uint32(uint32(len(records)))
	for _, record := range records {
		out = append(out, Uint32(uint32(record.Party))...)
		out = AppendBytes(out, record.Bytes)
	}
	return out
}

// DecodePartyBytes decodes party-scoped byte string records.
func DecodePartyBytes[T uint32Value](raw []byte, name string) ([]PartyBytes[T], error) {
	count, offset, err := ReadUint32(raw, 0)
	if err != nil {
		return nil, err
	}
	out := make([]PartyBytes[T], 0, count)
	for i := 0; i < int(count); i++ {
		party, next, err := ReadUint32(raw, offset)
		if err != nil {
			return nil, err
		}
		offset = next
		value, next, err := ReadBytes(raw, offset)
		if err != nil {
			return nil, err
		}
		offset = next
		out = append(out, PartyBytes[T]{Party: T(party), Bytes: value})
	}
	if offset != len(raw) {
		return nil, fmt.Errorf("trailing %s bytes", name)
	}
	return out, nil
}

// PartyBytesField decodes party-scoped byte string records from a wire field.
func PartyBytesField[T uint32Value](fields []wire.Field, tag uint16, name string) ([]PartyBytes[T], error) {
	raw, err := wire.Require(fields, tag)
	if err != nil {
		return nil, err
	}
	return DecodePartyBytes[T](raw, name)
}

// EncodePartyBytePairs encodes party-scoped pairs of byte string records.
func EncodePartyBytePairs[T uint32Value](records []PartyBytePair[T]) []byte {
	out := Uint32(uint32(len(records)))
	for _, record := range records {
		out = append(out, Uint32(uint32(record.Party))...)
		out = AppendBytes(out, record.First)
		out = AppendBytes(out, record.Second)
	}
	return out
}

// DecodePartyBytePairs decodes party-scoped pairs of byte string records.
func DecodePartyBytePairs[T uint32Value](raw []byte, name string) ([]PartyBytePair[T], error) {
	count, offset, err := ReadUint32(raw, 0)
	if err != nil {
		return nil, err
	}
	out := make([]PartyBytePair[T], 0, count)
	for i := 0; i < int(count); i++ {
		party, next, err := ReadUint32(raw, offset)
		if err != nil {
			return nil, err
		}
		offset = next
		first, next, err := ReadBytes(raw, offset)
		if err != nil {
			return nil, err
		}
		offset = next
		second, next, err := ReadBytes(raw, offset)
		if err != nil {
			return nil, err
		}
		offset = next
		out = append(out, PartyBytePair[T]{Party: T(party), First: first, Second: second})
	}
	if offset != len(raw) {
		return nil, fmt.Errorf("trailing %s bytes", name)
	}
	return out, nil
}

// PartyBytePairsField decodes party-scoped byte string pairs from a wire field.
func PartyBytePairsField[T uint32Value](fields []wire.Field, tag uint16, name string) ([]PartyBytePair[T], error) {
	raw, err := wire.Require(fields, tag)
	if err != nil {
		return nil, err
	}
	return DecodePartyBytePairs[T](raw, name)
}
