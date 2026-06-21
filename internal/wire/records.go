package wire

import (
	"errors"
	"fmt"
	"math"
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

// PartyTriple is a party-scoped triple of byte string records.
type PartyTriple[T uint32Value] struct {
	Party  T
	First  []byte
	Second []byte
	Third  []byte
}

// EncodeUint32ListChecked encodes a list of uint32-compatible values.
func EncodeUint32ListChecked[T uint32Value](items []T) ([]byte, error) {
	if uint64(len(items)) > math.MaxUint32 {
		return nil, fmt.Errorf("uint32 list count %d exceeds uint32", len(items))
	}
	out := Uint32(uint32(len(items)))
	for _, item := range items {
		out = append(out, Uint32(uint32(item))...)
	}
	return out, nil
}

// EncodeUint32List encodes a list of uint32-compatible values.
// It panics when the item count exceeds the wire uint32 count domain.
func EncodeUint32List[T uint32Value](items []T) []byte {
	out, err := EncodeUint32ListChecked(items)
	if err != nil {
		panic(err)
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
	if uint64(count) > uint64(maxRecordCount) {
		return nil, fmt.Errorf("uint32 list count too large: %d > %d", count, maxRecordCount)
	}
	if maxItems > 0 && uint64(count) > uint64(maxItems) {
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

// EncodeBytesListChecked encodes a list of byte strings with uint32 lengths.
func EncodeBytesListChecked(items [][]byte) ([]byte, error) {
	if uint64(len(items)) > math.MaxUint32 {
		return nil, fmt.Errorf("bytes list count %d exceeds uint32", len(items))
	}
	out := Uint32(uint32(len(items)))
	for i, item := range items {
		var err error
		out, err = AppendBytesChecked(out, item)
		if err != nil {
			return nil, fmt.Errorf("bytes list item %d: %w", i, err)
		}
	}
	return out, nil
}

// EncodeBytesList encodes a list of byte strings with uint32 lengths.
// It panics when a count or item length exceeds the wire uint32 domain.
func EncodeBytesList(items [][]byte) []byte {
	out, err := EncodeBytesListChecked(items)
	if err != nil {
		panic(err)
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

// EncodePartyBytesChecked encodes party-scoped byte string records.
func EncodePartyBytesChecked[T uint32Value](records []PartyBytes[T]) ([]byte, error) {
	if uint64(len(records)) > math.MaxUint32 {
		return nil, fmt.Errorf("party bytes count %d exceeds uint32", len(records))
	}
	out := Uint32(uint32(len(records)))
	for i, record := range records {
		out = append(out, Uint32(uint32(record.Party))...)
		var err error
		out, err = AppendBytesChecked(out, record.Bytes)
		if err != nil {
			return nil, fmt.Errorf("party bytes item %d: %w", i, err)
		}
	}
	return out, nil
}

// EncodePartyBytes encodes party-scoped byte string records.
// It panics when a count or item length exceeds the wire uint32 domain.
func EncodePartyBytes[T uint32Value](records []PartyBytes[T]) []byte {
	out, err := EncodePartyBytesChecked(records)
	if err != nil {
		panic(err)
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

// EncodePartyBytePairsChecked encodes party-scoped pairs of byte string records.
func EncodePartyBytePairsChecked[T uint32Value](records []PartyBytePair[T]) ([]byte, error) {
	if uint64(len(records)) > math.MaxUint32 {
		return nil, fmt.Errorf("party byte pair count %d exceeds uint32", len(records))
	}
	out := Uint32(uint32(len(records)))
	for i, record := range records {
		out = append(out, Uint32(uint32(record.Party))...)
		var err error
		out, err = AppendBytesChecked(out, record.First)
		if err != nil {
			return nil, fmt.Errorf("party byte pair item %d first: %w", i, err)
		}
		out, err = AppendBytesChecked(out, record.Second)
		if err != nil {
			return nil, fmt.Errorf("party byte pair item %d second: %w", i, err)
		}
	}
	return out, nil
}

// EncodePartyBytePairs encodes party-scoped pairs of byte string records.
// It panics when a count or item length exceeds the wire uint32 domain.
func EncodePartyBytePairs[T uint32Value](records []PartyBytePair[T]) []byte {
	out, err := EncodePartyBytePairsChecked(records)
	if err != nil {
		panic(err)
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

// EncodePartyTriplesChecked encodes party-scoped triples of byte string records.
func EncodePartyTriplesChecked[T uint32Value](records []PartyTriple[T]) ([]byte, error) {
	if uint64(len(records)) > math.MaxUint32 {
		return nil, fmt.Errorf("party triple count %d exceeds uint32", len(records))
	}
	out := Uint32(uint32(len(records)))
	for i, record := range records {
		out = append(out, Uint32(uint32(record.Party))...)
		var err error
		out, err = AppendBytesChecked(out, record.First)
		if err != nil {
			return nil, fmt.Errorf("party triple item %d first: %w", i, err)
		}
		out, err = AppendBytesChecked(out, record.Second)
		if err != nil {
			return nil, fmt.Errorf("party triple item %d second: %w", i, err)
		}
		out, err = AppendBytesChecked(out, record.Third)
		if err != nil {
			return nil, fmt.Errorf("party triple item %d third: %w", i, err)
		}
	}
	return out, nil
}

// EncodePartyTriples encodes party-scoped triples of byte string records.
// It panics when a count or item length exceeds the wire uint32 domain.
func EncodePartyTriples[T uint32Value](records []PartyTriple[T]) []byte {
	out, err := EncodePartyTriplesChecked(records)
	if err != nil {
		panic(err)
	}
	return out
}

// DecodePartyTriplesWithLimit decodes party-scoped triples with explicit per-field caps.
func DecodePartyTriplesWithLimit[T uint32Value](raw []byte, maxItems int, maxFirstBytes, maxSecondBytes, maxThirdBytes int, name string) ([]PartyTriple[T], error) {
	count, offset, err := ReadUint32(raw, 0)
	if err != nil {
		return nil, err
	}
	if err := validateRecordCountWithLimit(raw, offset, count, 16, maxItems, name); err != nil {
		return nil, err
	}
	out := make([]PartyTriple[T], 0, count)
	for i := 0; i < int(count); i++ {
		party, next, err := ReadUint32(raw, offset)
		if err != nil {
			return nil, err
		}
		offset = next
		first, next, err := ReadBytesWithLimit(raw, offset, maxFirstBytes)
		if err != nil {
			return nil, err
		}
		offset = next
		second, next, err := ReadBytesWithLimit(raw, offset, maxSecondBytes)
		if err != nil {
			return nil, err
		}
		offset = next
		third, next, err := ReadBytesWithLimit(raw, offset, maxThirdBytes)
		if err != nil {
			return nil, err
		}
		offset = next
		out = append(out, PartyTriple[T]{Party: T(party), First: first, Second: second, Third: third})
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
	if maxItems > 0 && uint64(count) > uint64(maxItems) {
		return fmt.Errorf("%s count too large: %d > %d", name, count, maxItems)
	}
	if uint64(count) > uint64(maxRecordCount) {
		return fmt.Errorf("%s count too large: %d > %d", name, count, maxRecordCount)
	}
	remaining := uint64(len(raw) - offset)
	minBytes := uint64(count) * uint64(minRecordLen)
	if remaining < minBytes {
		return fmt.Errorf("invalid %s length", name)
	}
	return nil
}
