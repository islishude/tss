package wire

import (
	"errors"
	"fmt"
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

// EncodeUint32List encodes a list of uint32-compatible values.
func EncodeUint32List[T uint32Value](items []T) []byte {
	out := Uint32(uint32(len(items)))
	for _, item := range items {
		out = append(out, Uint32(uint32(item))...)
	}
	return out
}

// DecodeUint32List decodes a list produced by EncodeUint32List.
func DecodeUint32List[T uint32Value](raw []byte) ([]T, error) {
	count, offset, err := ReadUint32(raw, 0)
	if err != nil {
		return nil, err
	}
	if uint64(len(raw)-offset) != uint64(count)*4 {
		return nil, errors.New("invalid party id list length")
	}
	out := make([]T, 0, count)
	for i := 0; i < int(count); i++ {
		value, next, err := ReadUint32(raw, offset)
		if err != nil {
			return nil, err
		}
		offset = next
		out = append(out, T(value))
	}
	return out, nil
}

// EncodeBytesList encodes a list of byte strings with uint32 lengths.
func EncodeBytesList(items [][]byte) []byte {
	out := Uint32(uint32(len(items)))
	for _, item := range items {
		out = AppendBytes(out, item)
	}
	return out
}

// DecodeBytesList decodes a list produced by EncodeBytesList.
func DecodeBytesList(raw []byte) ([][]byte, error) {
	count, offset, err := ReadUint32(raw, 0)
	if err != nil {
		return nil, err
	}
	out := make([][]byte, 0, count)
	for i := 0; i < int(count); i++ {
		item, next, err := ReadBytes(raw, offset)
		if err != nil {
			return nil, err
		}
		offset = next
		out = append(out, item)
	}
	if offset != len(raw) {
		return nil, errors.New("trailing bytes list data")
	}
	return out, nil
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
