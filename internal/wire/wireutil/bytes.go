package wireutil

import "slices"

// IsAllZero reports whether every byte in b is zero. The scan is constant-time:
// all bytes are accumulated with bitwise OR before the comparison, so the
// runtime does not depend on the position or number of non-zero bytes. A nil
// or empty slice returns true.
//
// Use IsAllZero when the timing of the check may reveal information about the
// content (e.g. verifying that a secret scalar or ciphertext has been cleared).
// For non-security-sensitive checks, [bytes.Equal] or a simple loop may be more
// readable.
func IsAllZero(b []byte) bool {
	var acc byte
	for _, x := range b {
		acc |= x
	}
	return acc == 0
}

// CloneByteSlices returns a deep copy of a [][]byte slice. A nil input returns nil.
func CloneByteSlices(in [][]byte) [][]byte {
	if in == nil {
		return nil
	}
	out := make([][]byte, len(in))
	for i := range in {
		out[i] = slices.Clone(in[i])
	}
	return out
}
