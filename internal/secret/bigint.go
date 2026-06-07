package secret

import "math/big"

// ClearBigInt zeros the allocated words behind x and resets x to zero.
func ClearBigInt(x *big.Int) {
	if x == nil {
		return
	}
	words := x.Bits()
	clear(words[:cap(words)])
	x.SetBits(nil)
}
