package signprep

import (
	"errors"
	"math/big"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	transcriptpkg "github.com/islishude/tss/internal/transcript"
)

const signPrepProofDomainLabel = "cggmp21-secp256k1-signprep-proof"

var errZeroChallenge = errors.New("signprep: zero challenge — re-run with fresh nonces")

func transcript(stmt Statement, kCommit, mCommit, dleqA1, dleqA2, mPoint []byte) (*big.Int, error) {
	t := transcriptpkg.New(signPrepProofDomainLabel)
	t.AppendString("protocol", string(stmt.Protocol))
	t.AppendBytes("session_id", stmt.SessionID[:])
	t.AppendUint32("party", uint32(stmt.Party))
	t.AppendUint32List("signers", transcriptpkg.Uint32s(stmt.Signers))
	t.AppendBytes("plan_hash", stmt.PlanHash)
	t.AppendBytes("context_hash", stmt.ContextHash)
	t.AppendBytes("additive_shift", stmt.AdditiveShift)
	t.AppendBytes("public_key", stmt.PublicKey)
	t.AppendBytes("keygen_transcript_hash", stmt.KeygenTranscriptHash)
	t.AppendBytes("parties_hash", stmt.PartiesHash)
	t.AppendBytes("enc_k", stmt.EncK)
	t.AppendBytes("paillier_public_key", stmt.PaillierPublicKey)
	t.AppendBytes("round1_echo", stmt.Round1Echo)
	t.AppendBytes("gamma", stmt.Gamma)
	t.AppendBytes("delta", stmt.Delta)
	t.AppendBytes("little_r", stmt.LittleR)
	t.AppendBytes("r", stmt.R)
	t.AppendBytes("k_point", stmt.KPoint)
	t.AppendBytes("chi_point", stmt.ChiPoint)
	t.AppendBytes("x_bar_point", stmt.XBarPoint)
	t.AppendBytes("m_point", mPoint)
	t.AppendBytes("k_commitment", kCommit)
	t.AppendBytes("m_commitment", mCommit)
	t.AppendBytes("dleq_a1", dleqA1)
	t.AppendBytes("dleq_a2", dleqA2)

	challenge := new(big.Int).SetBytes(t.Sum())
	challenge.Mod(challenge, secp.Order())
	if challenge.Sign() == 0 {
		return nil, errZeroChallenge
	}
	return challenge, nil
}
