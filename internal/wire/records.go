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
	return DecodeUint32ListWithLimit[T](raw, 0)
}

// DecodeUint32ListWithLimit decodes a uint32 list with an explicit item cap.
// When maxItems <= 0 the check is skipped; callers should prefer a real cap.
func DecodeUint32ListWithLimit[T uint32Value](raw []byte, maxItems int) ([]T, error) {
	count, offset, err := ReadUint32(raw, 0)
	if err != nil {
		return nil, err
	}
	if int(count) > maxRecordCount {
		return nil, fmt.Errorf("uint32 list count too large: %d > %d", count, maxRecordCount)
	}
	if maxItems > 0 && int(count) > maxItems {
		return nil, fmt.Errorf("uint32 list count too large: %d > %d", count, maxItems)
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
	return DecodeBytesListWithLimit(raw, 0, 0)
}

// DecodeBytesListWithLimit decodes a byte-string list with explicit caps.
// When maxItems or maxItemBytes is <= 0 the respective check is skipped.
func DecodeBytesListWithLimit(raw []byte, maxItems int, maxItemBytes int) ([][]byte, error) {
	count, offset, err := ReadUint32(raw, 0)
	if err != nil {
		return nil, err
	}
	if err := validateRecordCountWithLimit(raw, offset, count, 4, maxItems, "bytes list"); err != nil {
		return nil, err
	}
	out := make([][]byte, 0, count)
	for i := 0; i < int(count); i++ {
		item, next, err := ReadBytesWithLimit(raw, offset, maxItemBytes)
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
	return DecodePartyBytesWithLimit[T](raw, 0, 0, name)
}

// DecodePartyBytesWithLimit decodes party-scoped byte string records with explicit caps.
func DecodePartyBytesWithLimit[T uint32Value](raw []byte, maxItems int, maxItemBytes int, name string) ([]PartyBytes[T], error) {
	count, offset, err := ReadUint32(raw, 0)
	if err != nil {
		return nil, err
	}
	if err := validateRecordCountWithLimit(raw, offset, count, 8, maxItems, name); err != nil {
		return nil, err
	}
	out := make([]PartyBytes[T], 0, count)
	for i := 0; i < int(count); i++ {
		party, next, err := ReadUint32(raw, offset)
		if err != nil {
			return nil, err
		}
		offset = next
		value, next, err := ReadBytesWithLimit(raw, offset, maxItemBytes)
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
	return DecodePartyBytePairsWithLimit[T](raw, 0, 0, name)
}

// DecodePartyBytePairsWithLimit decodes party-scoped pairs with explicit caps.
func DecodePartyBytePairsWithLimit[T uint32Value](raw []byte, maxItems int, maxItemBytes int, name string) ([]PartyBytePair[T], error) {
	count, offset, err := ReadUint32(raw, 0)
	if err != nil {
		return nil, err
	}
	if err := validateRecordCountWithLimit(raw, offset, count, 12, maxItems, name); err != nil {
		return nil, err
	}
	out := make([]PartyBytePair[T], 0, count)
	for i := 0; i < int(count); i++ {
		party, next, err := ReadUint32(raw, offset)
		if err != nil {
			return nil, err
		}
		offset = next
		first, next, err := ReadBytesWithLimit(raw, offset, maxItemBytes)
		if err != nil {
			return nil, err
		}
		offset = next
		second, next, err := ReadBytesWithLimit(raw, offset, maxItemBytes)
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

// maxRecordCount is the absolute maximum number of items in any repeated wire field.
// It matches max(uint16) which is the wire format's field count ceiling.
const maxRecordCount = 65535

func validateRecordCountWithLimit(raw []byte, offset int, count uint32, minRecordLen int, maxItems int, name string) error {
	if offset > len(raw) {
		return fmt.Errorf("invalid %s offset", name)
	}
	if maxItems > 0 && int(count) > maxItems {
		return fmt.Errorf("%s count too large: %d > %d", name, count, maxItems)
	}
	if int(count) > maxRecordCount {
		return fmt.Errorf("%s count too large: %d > %d", name, count, maxRecordCount)
	}
	remaining := uint64(len(raw) - offset)
	minBytes := uint64(count) * uint64(minRecordLen)
	if remaining < minBytes {
		return fmt.Errorf("invalid %s length", name)
	}
	return nil
}
