package wireutil

import (
	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/transcript"
)

// PartySetHash returns a SHA-256 digest that binds a label and a sorted party set.
//
// Parties are sorted with [tss.SortParties] before hashing so that the same set
// always produces the same 32-byte digest regardless of input order.
//
// Different labels guarantee domain separation — the same party set hashed under
// "keygen" and "signing" labels will produce distinct digests.
func PartySetHash(parties []tss.PartyID, label string) []byte {
	t := transcript.New(label)
	t.AppendUint32List("parties", tss.SortParties(parties))
	return t.Sum()
}

// ByteSlicesHash returns a SHA-256 digest that binds a label and a sequence of byte slices.
//
// Values are encoded as a canonical byte-string list, which prevents
// concatenation collisions: hashing ["ab", "c"] and ["a", "bc"] produces
// different digests.
//
// Different labels guarantee domain separation. A nil or empty values slice is valid and
// produces a digest over the label alone.
func ByteSlicesHash(label string, values [][]byte) []byte {
	t := transcript.New(label)
	t.AppendBytesList("values", values)
	return t.Sum()
}
