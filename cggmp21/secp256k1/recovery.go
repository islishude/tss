package secp256k1

import (
	"bytes"
	"errors"
	"math/big"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
)

// signatureRecoveryIDMatchesPublicKey checks the recoverable-signature semantic
// that ordinary ECDSA verification omits: the stored recovery ID must select
// the exact public key bound to the sign attempt.
func signatureRecoveryIDMatchesPublicKey(publicKey, digest []byte, sig *Signature) bool {
	if sig == nil || sig.RecoveryID > 3 || len(digest) != 32 {
		return false
	}
	r, err := secp.ScalarFromBytes(sig.R)
	if err != nil {
		return false
	}
	s, err := secp.ScalarFromBytes(sig.S)
	if err != nil {
		return false
	}

	// Recovery bit 1 selects x=r+n. PointFromBytes also rejects x >= p and
	// non-residues, so malformed recovery points fail closed.
	x := new(big.Int).SetBytes(sig.R)
	if sig.RecoveryID&2 != 0 {
		x.Add(x, secp.Order())
	}
	if x.BitLen() > 256 {
		return false
	}
	compressedR := make([]byte, secp.PubkeyLength)
	compressedR[0] = 0x02 | (sig.RecoveryID & 1)
	x.FillBytes(compressedR[1:])
	recoveryPoint, err := secp.PointFromBytes(compressedR)
	if err != nil {
		return false
	}

	z, err := secp.ScalarFromBytesModOrder(digest)
	if err != nil {
		return false
	}
	rInv, err := secp.ScalarInvert(r)
	if err != nil {
		return false
	}
	// Q = r^-1 * (sR - zG).
	candidate := secp.ScalarMult(
		secp.Add(secp.ScalarMult(recoveryPoint, s), secp.ScalarBaseMult(secp.ScalarNeg(z))),
		rInv,
	)
	candidateBytes, err := secp.PointBytes(candidate)
	if err != nil {
		return false
	}
	return bytes.Equal(candidateBytes, publicKey)
}

// recoveryIDFromPresignR computes the compact secp256k1 ECDSA recovery ID (0-3)
// from the compressed presign nonce point R without decompressing the point.
// The recovery ID encodes two bits:
//
//	bit 0 — Y parity of R (0 = even, 1 = odd)
//	bit 1 — whether R.X >= n (curve order)
//
// Y parity is read directly from the SEC1 prefix byte (0x02 = even, 0x03 = odd).
// X comparison is performed on the raw 32-byte coordinate via [secp.XCoordGTEOrder].
//
// When sWasNegated is true (low-S normalization occurred), the recovery point becomes -R:
// X is unchanged but Y parity flips, so bit 0 is inverted.
func recoveryIDFromPresignR(rPointBytes []byte, sWasNegated bool) (uint8, error) {
	if len(rPointBytes) != secp.PubkeyLength || (rPointBytes[0] != 0x02 && rPointBytes[0] != 0x03) {
		return 0, errors.New("invalid presign R point: must be 33-byte compressed SEC1")
	}

	var recid uint8

	// Bit 0: Y parity. 0x02 = even, 0x03 = odd.
	if rPointBytes[0] == 0x03 {
		recid |= 1
	}

	// Bit 1: whether R.X >= n.
	if secp.XCoordGTEOrder(rPointBytes[1:33]) {
		recid |= 2
	}

	// If s was normalized from high-S to n-s, ECDSA recovery must use -R.
	// X is unchanged; Y parity flips.
	if sWasNegated {
		recid ^= 1
	}

	return recid, nil
}

// Compact65 returns the 65-byte compact recoverable signature format:
// [R (32 bytes)] [S (32 bytes)] [RecoveryID (1 byte)].
func (sig *Signature) Compact65() []byte {
	out := make([]byte, 65)
	copy(out[0:32], sig.R)
	copy(out[32:64], sig.S)
	out[64] = sig.RecoveryID
	return out
}

// EthereumYParity returns the Ethereum-style yParity (0 or 1) for
// post-EIP-155 transaction encoding. It extracts the LSB of the recovery ID.
func (sig *Signature) EthereumYParity() uint8 {
	return sig.RecoveryID & 1
}
