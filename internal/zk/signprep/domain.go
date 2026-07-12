package signprep

import (
	"errors"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	transcriptpkg "github.com/islishude/tss/internal/transcript"
)

const signPrepProofDomainLabel = "cggmp21-secp256k1-signprep-proof"

var errZeroChallenge = errors.New("signprep: zero challenge — re-run with fresh nonces")

func transcript(stmt Statement, kCommit, mCommit, dleqA1, dleqA2, mtaRelationCommitment, deltaRelationCommitment, mPoint []byte) (secp.Scalar, error) {
	t := transcriptpkg.New(signPrepProofDomainLabel)
	t.AppendString("protocol", string(stmt.Protocol))
	t.AppendBytes("session_id", stmt.SessionID[:])
	t.AppendUint32("party", stmt.Party)
	t.AppendUint32List("signers", stmt.Signers)
	t.AppendBytes("plan_hash", stmt.PlanHash)
	t.AppendBytes("context_hash", stmt.ContextHash)
	t.AppendBytes("additive_shift", stmt.AdditiveShift)
	t.AppendBytes("public_key", stmt.PublicKey)
	t.AppendBytes("keygen_transcript_hash", stmt.KeygenTranscriptHash)
	t.AppendBytes("parties_hash", stmt.PartiesHash)
	t.AppendBytes("enc_k", stmt.EncK)
	t.AppendBytes("paillier_public_key", stmt.PaillierPublicKey)
	t.AppendBytes("round1_echo", stmt.Round1Echo)
	t.AppendBytes("round2_commitments_hash", stmt.Round2CommitmentsHash)
	t.AppendBytes("mta_contributions_hash", stmt.MTAContributionsHash)
	t.AppendBytes("mta_base_point", stmt.MTABasePoint)
	t.AppendBytes("mta_offset_point", stmt.MTAOffsetPoint)
	t.AppendBytes("delta_base_point", stmt.DeltaBasePoint)
	t.AppendBytes("delta_offset_point", stmt.DeltaOffsetPoint)
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
	t.AppendBytes("mta_relation_commitment", mtaRelationCommitment)
	t.AppendBytes("delta_relation_commitment", deltaRelationCommitment)

	challenge, err := secp.ScalarFromBytesModOrder(t.Sum())
	if err != nil {
		return secp.Scalar{}, err
	}
	if challenge.IsZero() {
		return secp.Scalar{}, errZeroChallenge
	}
	return challenge, nil
}
