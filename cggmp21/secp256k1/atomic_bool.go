package secp256k1

import "sync/atomic"

type atomicBool struct {
	*atomic.Bool
}

func newAtomicBool() atomicBool {
	b := new(atomic.Bool)
	return atomicBool{Bool: b}
}
