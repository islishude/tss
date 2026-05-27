package wire

import "io"

// WriteHashPart writes part to w with a 4-byte big-endian length prefix.
func WriteHashPart(w io.Writer, part []byte) {
	_, _ = w.Write([]byte{byte(len(part) >> 24), byte(len(part) >> 16), byte(len(part) >> 8), byte(len(part))})
	_, _ = w.Write(part)
}

// WritePartyID writes id as a length-prefixed 4-byte big-endian value.
func WritePartyID[T uint32Value](w io.Writer, id T) {
	WriteHashPart(w, []byte{byte(id >> 24), byte(id >> 16), byte(id >> 8), byte(id)})
}

// WritePartySet writes the length-prefixed sorted party set.
func WritePartySet[T uint32Value](w io.Writer, parties []T) {
	WriteHashPart(w, Uint32(uint32(len(parties))))
	for _, id := range parties {
		WritePartyID(w, id)
	}
}
