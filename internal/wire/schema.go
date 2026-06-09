package wire

import (
	"fmt"
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

// parseFieldTag parses a wire struct tag like `"1,bytes,max_bytes=field"`.
func parseFieldTag(f reflect.StructField, tagStr string) (fieldSchema, error) {
	parts := strings.Split(tagStr, ",")
	if len(parts) < 2 {
		return fieldSchema{}, fmt.Errorf("invalid wire tag %q (need <tag>,<kind>)", tagStr)
	}

	tag, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 16)
	if err != nil {
		return fieldSchema{}, fmt.Errorf("invalid tag number %q", parts[0])
	}
	if tag < 1 || tag > 65535 {
		return fieldSchema{}, fmt.Errorf("tag must be in [1, 65535]: %d", tag)
	}

	kindStr := strings.TrimSpace(parts[1])
	kind, err := parseKind(kindStr, f.Type)
	if err != nil {
		return fieldSchema{}, err
	}

	fs := fieldSchema{
		tag:   uint16(tag),
		name:  f.Name,
		index: f.Index,
		kind:  kind,
		typ:   f.Type,
	}

	// Parse options.
	for _, opt := range parts[2:] {
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
			if n < 0 {
				return fieldSchema{}, fmt.Errorf("len must be non-negative")
			}
			fs.fixedLen = n
		case "max_bytes":
			fs.maxBytes = val
		case "max_items":
			fs.maxItems = val
		default:
			return fieldSchema{}, fmt.Errorf("unknown option %q", key)
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
			return 0, fmt.Errorf("u32list requires slice, got %s", t)
		}
		return kindU32List, nil
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
	default:
		return 0, fmt.Errorf("unknown wire kind %q", kindStr)
	}
}
