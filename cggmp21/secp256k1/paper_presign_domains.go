package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"errors"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/transcript"
	"github.com/islishude/tss/internal/wire"
)

const paperPresignProofDomainLabel = "cggmp21-secp256k1-figure8-proof-domain"

func requireFigure8Binding(gotEpoch, gotPresign, wantEpoch, wantPresign []byte) error {
	if len(gotEpoch) != sha256.Size || !bytes.Equal(gotEpoch, wantEpoch) {
		return errors.New("figure 8 epoch binding mismatch")
	}
	if len(gotPresign) != sha256.Size || !bytes.Equal(gotPresign, wantPresign) {
		return errors.New("figure 8 presign id binding mismatch")
	}
	return nil
}

func figure8ProofDomain(
	sessionID tss.SessionID,
	epochID, presignID, planHash, contextHash []byte,
	signers tss.PartySet,
	round uint8,
	prover, verifier tss.PartyID,
	relation string,
) ([]byte, error) {
	if !sessionID.Valid() {
		return nil, tss.ErrInvalidSessionID
	}
	for _, field := range []struct {
		name  string
		value []byte
	}{{"epoch id", epochID}, {"presign id", presignID}, {"plan hash", planHash}, {"context hash", contextHash}} {
		if len(field.value) != sha256.Size {
			return nil, errors.New("Figure 8 " + field.name + " must be 32 bytes")
		}
	}
	if err := wire.ValidateStrictSortedIDs(signers); err != nil {
		return nil, err
	}
	if !tss.ContainsParty(signers, prover) ||
		(verifier != tss.BroadcastPartyId && !tss.ContainsParty(signers, verifier)) {
		return nil, errors.New("figure 8 proof party is outside signer set")
	}
	if relation == "" || round < presignStartRound || round > presignRound3 {
		return nil, errors.New("invalid Figure 8 proof relation or round")
	}
	t := transcript.New(paperPresignProofDomainLabel)
	t.AppendBytes("protocol", []byte(tss.ProtocolCGGMP21Secp256k1))
	t.AppendBytes("session_id", sessionID[:])
	t.AppendBytes("epoch_id", epochID)
	t.AppendBytes("presign_id", presignID)
	t.AppendBytes("plan_hash", planHash)
	t.AppendBytes("context_hash", contextHash)
	t.AppendUint32List("signers", signers)
	t.AppendUint32("round", uint32(round))
	t.AppendUint32("prover", prover)
	t.AppendUint32("verifier", verifier)
	t.AppendBytes("relation", []byte(relation))
	return t.Sum(), nil
}
