package wireutil

import (
	"crypto/sha256"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/wire"
)

// PartySetHash returns a SHA-256 digest that binds a label and a sorted party set.
//
// The label is written first (length-prefixed via [wire.WriteHashPart]), followed by
// each party ID (length-prefixed 4-byte big-endian via [wire.WritePartyID]). Parties
// are sorted with [tss.SortParties] before hashing so that the same set always produces
// the same 32-byte digest regardless of input order.
//
// Different labels guarantee domain separation — the same party set hashed under
// "keygen" and "signing" labels will produce distinct digests.
func PartySetHash(parties []tss.PartyID, label string) []byte {
	h := sha256.New()
	wire.WriteHashPart(h, []byte(label))
	for _, id := range tss.SortParties(parties) {
		wire.WritePartyID(h, id)
	}
	return h.Sum(nil)
}

// ByteSlicesHash returns a SHA-256 digest that binds a label and a sequence of byte slices.
//
// The label is written first (length-prefixed via [wire.WriteHashPart]), followed by
// each byte slice in order. Every element — label and slices alike — is length-prefixed
// by [wire.WriteHashPart], which prevents concatenation collisions: hashing ["ab", "c"]
// and ["a", "bc"] will produce different digests.
//
// Different labels guarantee domain separation. A nil or empty values slice is valid and
// produces a digest over the label alone.
func ByteSlicesHash(label string, values [][]byte) []byte {
	h := sha256.New()
	wire.WriteHashPart(h, []byte(label))
	for _, value := range values {
		wire.WriteHashPart(h, value)
	}
	return h.Sum(nil)
}
