package signprep

import (
	"crypto/sha256"
	"errors"
	"math/big"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/wire"
)

const signPrepProofDomainLabel = "cggmp21-secp256k1-signprep-proof"

var errZeroChallenge = errors.New("signprep: zero challenge — re-run with fresh nonces")

func transcript(stmt Statement, kCommit, mCommit, dleqA1, dleqA2, mPoint []byte) (*big.Int, error) {
	h := sha256.New()
	write := func(b []byte) { wire.WriteHashPart(h, b) }

	write([]byte(signPrepProofDomainLabel))
	write([]byte(stmt.Protocol))
	write(stmt.SessionID[:])
	write(wire.Uint32(uint32(stmt.Party)))
	for _, id := range stmt.Signers {
		write(wire.Uint32(uint32(id)))
	}
	write(stmt.ContextHash)
	write(stmt.AdditiveShift)
	write(stmt.PublicKey)
	write(stmt.KeygenTranscriptHash)
	write(stmt.PartiesHash)
	write(stmt.EncK)
	write(stmt.PaillierPublicKey)
	write(stmt.Round1Echo)
	write(stmt.Gamma)
	write(stmt.Delta)
	write(stmt.LittleR)
	write(stmt.R)
	write(stmt.KPoint)
	write(stmt.ChiPoint)
	write(stmt.XBarPoint)
	write(mPoint)
	write(kCommit)
	write(mCommit)
	write(dleqA1)
	write(dleqA2)

	challenge := new(big.Int).SetBytes(h.Sum(nil))
	challenge.Mod(challenge, secp.Order())
	if challenge.Sign() == 0 {
		return nil, errZeroChallenge
	}
	return challenge, nil
}
