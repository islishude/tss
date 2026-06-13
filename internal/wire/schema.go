package wire

import (
	"fmt"
	"math/big"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// wireKind enumerates the encodable field types.
type wireKind uint8

const (
	kindU8 wireKind = iota
	kindU16
	kindU32
	kindBool
	kindBytes
	kindString
	kindU32List
	kindBytesList
	kindPartyBytes
	kindPartyBytePairs
	kindNested
	kindCustom
	kindBigInt
	kindBigUint
	kindBigPos
	kindRecord
	kindRecordList
)

// fieldSchema holds the parsed information for a single wire-tagged struct field.
type fieldSchema struct {
	tag      uint16
	name     string
	index    []int
	kind     wireKind
	typ      reflect.Type
	fixedLen int    // for len=N option
	maxBytes string // limit name for max_bytes= option
	maxItems string // limit name for max_items= option
	maxBits  string // limit name for max_bits= option
}

// schema is the cached parsed struct-tag information for a wire-encodable type.
type schema struct {
	typ    reflect.Type
	fields []fieldSchema // sorted by tag
}

var schemaCache sync.Map // map[reflect.Type]*schema

func getSchema(t reflect.Type) (*schema, error) {
	if cached, ok := schemaCache.Load(t); ok {
		s := cached.(*schema)
		if s.typ == t {
			return s, nil
		}
	}
	s, err := parseSchema(t)
	if err != nil {
		return nil, err
	}
	actual, _ := schemaCache.LoadOrStore(t, s)
	return actual.(*schema), nil
}

// FieldTag returns the wire tag number for the named field of model.
// model must be a non-nil struct with a `wire:"N,…"` tag on every encoded field.
func FieldTag(model any, fieldName string) (uint16, error) {
	t := reflect.TypeOf(model)
	s, err := getSchema(t)
	if err != nil {
		return 0, err
	}
	for _, f := range s.fields {
		if f.name == fieldName {
			return f.tag, nil
		}
	}
	return 0, fmt.Errorf("wire.FieldTag: field %q not found in %s", fieldName, t.Name())
}

func parseSchema(t reflect.Type) (*schema, error) {
	if t.Kind() != reflect.Struct {
		return nil, fmt.Errorf("expected struct, got %s", t.Kind())
	}

	var fields []fieldSchema
	seenTags := make(map[uint16]bool)

	for f := range t.Fields() {
		if !f.IsExported() {
			continue
		}
		tagStr, ok := f.Tag.Lookup("wire")
		if !ok {
			continue
		}
		if tagStr == "-" {
			continue
		}

		fs, err := parseFieldTag(f, tagStr)
		if err != nil {
			return nil, fmt.Errorf("field %s: %w", f.Name, err)
		}
		if seenTags[fs.tag] {
			return nil, fmt.Errorf("field %s: duplicate tag %d", f.Name, fs.tag)
		}
		seenTags[fs.tag] = true

		fields = append(fields, fs)
	}

	if len(fields) == 0 {
		return nil, fmt.Errorf("no wire-tagged fields in %s", t.Name())
	}

	// Sort by tag.
	sort.Slice(fields, func(i, j int) bool {
		return fields[i].tag < fields[j].tag
	})

	return &schema{typ: t, fields: fields}, nil
}

// parseFieldTag parses a wire struct tag.
//
// Supported forms:
//
//	wire:"<tag>"
//	wire:"<tag>,<kind>"
//	wire:"<tag>,<option>"
//	wire:"<tag>,<kind>,<option>"
//
// When the kind is omitted or the second segment is not a known kind name,
// the kind is inferred from the Go field type.
func parseFieldTag(f reflect.StructField, tagStr string) (fieldSchema, error) {
	parts := strings.Split(tagStr, ",")
	if len(parts) == 0 {
		return fieldSchema{}, fmt.Errorf("empty wire tag")
	}

	tag, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 16)
	if err != nil {
		return fieldSchema{}, fmt.Errorf("invalid tag number %q", parts[0])
	}
	if tag < 1 || tag > 65535 {
		return fieldSchema{}, fmt.Errorf("tag must be in [1, 65535]: %d", tag)
	}

	var kind wireKind
	optStart := 1 // first option index after tag

	if len(parts) > 1 {
		kindStr := strings.TrimSpace(parts[1])
		if isKnownKind(kindStr) {
			kind, err = parseKind(kindStr, f.Type)
			if err != nil {
				return fieldSchema{}, err
			}
			optStart = 2
		} else {
			// Second segment is not a known kind — infer from Go type.
			kind, err = inferKind(f.Type)
			if err != nil {
				return fieldSchema{}, err
			}
			optStart = 1
		}
	} else {
		kind, err = inferKind(f.Type)
		if err != nil {
			return fieldSchema{}, err
		}
	}

	fs := fieldSchema{
		tag:   uint16(tag),
		name:  f.Name,
		index: f.Index,
		kind:  kind,
		typ:   f.Type,
	}

	// Parse options.
	for _, opt := range parts[optStart:] {
		opt = strings.TrimSpace(opt)
		if opt == "" {
			continue
		}
		if opt == "allow_empty" {
			// Documented but no-op; empty is allowed by default.
			continue
		}
		kv := strings.SplitN(opt, "=", 2)
		if len(kv) != 2 {
			return fieldSchema{}, fmt.Errorf("invalid option %q", opt)
		}
		key := strings.TrimSpace(kv[0])
		val := strings.TrimSpace(kv[1])

		switch key {
		case "len":
			n, err := strconv.Atoi(val)
			if err != nil {
				return fieldSchema{}, fmt.Errorf("invalid len value %q", val)
			}
			if n <= 0 {
				return fieldSchema{}, fmt.Errorf("len must be positive")
			}
			fs.fixedLen = n
		case "max_bytes":
			fs.maxBytes = val
		case "max_items":
			fs.maxItems = val
		case "max_bits":
			fs.maxBits = val
		default:
			return fieldSchema{}, fmt.Errorf("unknown option %q", key)
		}
	}

	// Validate len=N against array length for bytes fields.
	if fs.kind == kindBytes && fs.fixedLen > 0 && f.Type.Kind() == reflect.Array {
		if f.Type.Len() != fs.fixedLen {
			return fieldSchema{}, fmt.Errorf("field %s: len=%d does not match array length %d", f.Name, fs.fixedLen, f.Type.Len())
		}
	}
	return fs, nil
}

// parseKind validates and returns the wireKind for a given string and Go type.
func parseKind(kindStr string, t reflect.Type) (wireKind, error) {
	switch kindStr {
	case "u8":
		if t.Kind() != reflect.Uint8 {
			return 0, fmt.Errorf("u8 requires uint8, got %s", t)
		}
		return kindU8, nil
	case "u16":
		if t.Kind() != reflect.Uint16 {
			return 0, fmt.Errorf("u16 requires uint16, got %s", t)
		}
		return kindU16, nil
	case "u32":
		switch t.Kind() {
		case reflect.Uint32, reflect.Int:
			return kindU32, nil
		default:
			return 0, fmt.Errorf("u32 requires uint32 or int, got %s", t)
		}
	case "bool":
		if t.Kind() != reflect.Bool {
			return 0, fmt.Errorf("bool requires bool, got %s", t)
		}
		return kindBool, nil
	case "bytes":
		switch t.Kind() {
		case reflect.Slice, reflect.Array:
			if t.Elem().Kind() != reflect.Uint8 {
				return 0, fmt.Errorf("bytes requires []byte or [N]byte, got %s", t)
			}
			return kindBytes, nil
		default:
			return 0, fmt.Errorf("bytes requires []byte or [N]byte, got %s", t)
		}
	case "string":
		if t.Kind() != reflect.String {
			return 0, fmt.Errorf("string requires string, got %s", t)
		}
		return kindString, nil
	case "u32list":
		if t.Kind() != reflect.Slice {
			return 0, fmt.Errorf("u32list requires []uint32 or []int, got %s", t)
		}
		elem := indirectType(t.Elem())
		switch elem.Kind() {
		case reflect.Uint32, reflect.Int:
			return kindU32List, nil
		default:
			return 0, fmt.Errorf("u32list requires []uint32 or []int, got %s", t)
		}
	case "byteslist":
		if t.Kind() != reflect.Slice {
			return 0, fmt.Errorf("byteslist requires slice, got %s", t)
		}
		if t.Elem().Kind() != reflect.Slice || t.Elem().Elem().Kind() != reflect.Uint8 {
			return 0, fmt.Errorf("byteslist requires [][]byte, got %s", t)
		}
		return kindBytesList, nil
	case "partybytes":
		if t.Kind() != reflect.Slice {
			return 0, fmt.Errorf("partybytes requires []PartyBytes[T], got %s", t)
		}
		return kindPartyBytes, nil
	case "partybytepairs":
		if t.Kind() != reflect.Slice {
			return 0, fmt.Errorf("partybytepairs requires []PartyBytePair[T], got %s", t)
		}
		return kindPartyBytePairs, nil
	case "nested":
		msgType := reflect.TypeFor[Message]()
		if !t.Implements(msgType) && !reflect.PointerTo(t).Implements(msgType) {
			return 0, fmt.Errorf("nested requires Message implementation, got %s", t)
		}
		return kindNested, nil
	case "custom":
		// Any type is accepted at schema-parse time. Interface checks
		// (ValueMarshaler / ValueUnmarshaler) happen at encode/decode.
		return kindCustom, nil
	case "bigint":
		bigType := reflect.TypeFor[big.Int]()
		ptrBigType := reflect.TypeFor[*big.Int]()
		if t != bigType && t != ptrBigType {
			return 0, fmt.Errorf("bigint requires big.Int or *big.Int, got %s", t)
		}
		return kindBigInt, nil
	case "biguint":
		bigType := reflect.TypeFor[big.Int]()
		ptrBigType := reflect.TypeFor[*big.Int]()
		if t != bigType && t != ptrBigType {
			return 0, fmt.Errorf("biguint requires big.Int or *big.Int, got %s", t)
		}
		return kindBigUint, nil
	case "bigpos":
		bigType := reflect.TypeFor[big.Int]()
		ptrBigType := reflect.TypeFor[*big.Int]()
		if t != bigType && t != ptrBigType {
			return 0, fmt.Errorf("bigpos requires big.Int or *big.Int, got %s", t)
		}
		return kindBigPos, nil
	case "record":
		if indirectType(t).Kind() != reflect.Struct {
			return 0, fmt.Errorf("record requires struct or *struct, got %s", t)
		}
		return kindRecord, nil
	case "recordlist":
		if t.Kind() != reflect.Slice || indirectType(t.Elem()).Kind() != reflect.Struct {
			return 0, fmt.Errorf("recordlist requires []struct or []*struct, got %s", t)
		}
		return kindRecordList, nil
	default:
		return 0, fmt.Errorf("unknown wire kind %q", kindStr)
	}
}

// knownKindNames is the set of wire kind names that must be explicitly declared.
var knownKindNames = map[string]bool{
	"u8": true, "u16": true, "u32": true, "bool": true,
	"bytes": true, "string": true, "u32list": true, "byteslist": true,
	"partybytes": true, "partybytepairs": true, "nested": true, "custom": true,
	"bigint": true, "biguint": true, "bigpos": true, "record": true, "recordlist": true,
}

// isKnownKind reports whether s is a recognized wire kind name.
func isKnownKind(s string) bool {
	return knownKindNames[s]
}

// inferKind returns the wire kind for a Go type when the tag omits an explicit kind.
//
// Mapping:
//
//	uint8                -> u8
//	uint16               -> u16
//	uint32 / int         -> u32 (int must be >= 0 and <= MaxUint32 at encode time)
//	bool                 -> bool
//	string / named string -> string
//	[]byte / [N]byte     -> bytes
//	[]uint32 / []int     -> u32list
//	[][]byte             -> byteslist
//	struct               -> record
//	*struct              -> record
//	[]struct / []*struct -> recordlist
//	ValueMarshaler       -> custom
//
// big.Int is NOT auto-inferred (three possible signedness variants).
func inferKind(t reflect.Type) (wireKind, error) {
	t = indirectType(t)

	// Check for ValueMarshaler first — domain types like SessionID, PartyID,
	// and other named primitives may implement it for custom encoding.
	vmType := reflect.TypeFor[ValueMarshaler]()
	if t.Implements(vmType) || reflect.PointerTo(t).Implements(vmType) {
		return kindCustom, nil
	}

	switch t.Kind() {
	case reflect.Uint8:
		return kindU8, nil
	case reflect.Uint16:
		return kindU16, nil
	case reflect.Uint32, reflect.Int:
		return kindU32, nil
	case reflect.Bool:
		return kindBool, nil
	case reflect.String:
		return kindString, nil
	case reflect.Slice:
		return inferSliceKind(t)
	case reflect.Array:
		if t.Elem().Kind() == reflect.Uint8 {
			return kindBytes, nil
		}
		return 0, fmt.Errorf("cannot infer wire kind for array of %s", t.Elem().Kind())
	case reflect.Struct:
		return kindRecord, nil
	case reflect.Pointer:
		elem := t.Elem()
		if elem.Kind() == reflect.Struct {
			return kindRecord, nil
		}
		return 0, fmt.Errorf("cannot infer wire kind for pointer to %s", elem.Kind())
	default:
		return 0, fmt.Errorf("cannot infer wire kind for %s", t.Kind())
	}
}

// inferSliceKind returns the wire kind for a slice type.
func inferSliceKind(t reflect.Type) (wireKind, error) {
	elem := indirectType(t.Elem())
	switch elem.Kind() {
	case reflect.Uint8:
		return kindBytes, nil
	case reflect.Uint32, reflect.Int:
		return kindU32List, nil
	case reflect.Slice:
		if elem.Elem().Kind() == reflect.Uint8 {
			return kindBytesList, nil
		}
		return 0, fmt.Errorf("cannot infer wire kind for [][]%s", elem.Elem().Kind())
	case reflect.Struct:
		return kindRecordList, nil
	case reflect.Pointer:
		if elem.Elem().Kind() == reflect.Struct {
			return kindRecordList, nil
		}
		return 0, fmt.Errorf("cannot infer wire kind for []*%s", elem.Elem().Kind())
	default:
		return 0, fmt.Errorf("cannot infer wire kind for []%s", elem.Kind())
	}
}

// indirectType returns the type T for a named type defined as T.
func indirectType(t reflect.Type) reflect.Type {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t
}
