package ed25519

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/transcript"
	"github.com/islishude/tss/internal/zk/schnorred25519"
)

const frostKeygenProofDomainLabel = "frost-ed25519-keygen-constant-proof-v1"

type frostKeygenProofStatement struct {
	ciphersuite           string
	protocol              tss.ProtocolID
	version               uint16
	sessionID             tss.SessionID
	round                 uint8
	dealer                tss.PartyID
	threshold             int
	parties               tss.PartySet
	planHash              []byte
	coefficientCommitment [][]byte
	chainCodeCommitment   []byte
}

func prepareFROSTKeygenProof(cfg tss.ThresholdConfig, planHash []byte, material *frostKeygenLocalMaterial) error {
	if material == nil || material.commitments == nil || len(material.polynomial) == 0 || material.polynomial[0] == nil {
		return errors.New("missing local material for keygen constant-term proof")
	}
	constant, err := material.commitments.PointAt(0)
	if err != nil {
		return err
	}
	secretConstant, err := newEdSecretScalarFromFed(material.polynomial[0])
	if err != nil {
		return err
	}
	defer secretConstant.Destroy()
	preparation, err := schnorred25519.Prepare(cfg.Reader(), constant.Bytes())
	if err != nil {
		return err
	}
	defer preparation.Destroy()
	domain := frostKeygenProofDomain(cfg, planHash, cfg.Self, *material.commitments, material.chainCodeCommit)
	proof, err := preparation.Finalize(domain, secretConstant)
	if err != nil {
		return err
	}
	material.proof = proof
	return nil
}

func verifyFROSTKeygenProof(cfg tss.ThresholdConfig, planHash []byte, dealer tss.PartyID, commitments keygenCommitments, chainCodeCommit []byte, proof *schnorred25519.Proof) error {
	constant, err := commitments.PointAt(0)
	if err != nil {
		return err
	}
	domain := frostKeygenProofDomain(cfg, planHash, dealer, commitments, chainCodeCommit)
	if !schnorred25519.Verify(domain, constant.Bytes(), proof) {
		return errors.New("invalid keygen constant-term proof")
	}
	return nil
}

func frostKeygenProofDomain(cfg tss.ThresholdConfig, planHash []byte, dealer tss.PartyID, commitments keygenCommitments, chainCodeCommit []byte) []byte {
	return newFROSTKeygenProofStatement(cfg, planHash, dealer, commitments, chainCodeCommit).domain()
}

func newFROSTKeygenProofStatement(cfg tss.ThresholdConfig, planHash []byte, dealer tss.PartyID, commitments keygenCommitments, chainCodeCommit []byte) frostKeygenProofStatement {
	return frostKeygenProofStatement{
		ciphersuite:           rfc9591ContextString,
		protocol:              tss.ProtocolFROSTEd25519,
		version:               tss.ProtocolVersion,
		sessionID:             cfg.SessionID,
		round:                 keygenCommitmentRound,
		dealer:                dealer,
		threshold:             cfg.Threshold,
		parties:               cfg.Parties.Clone(),
		planHash:              bytes.Clone(planHash),
		coefficientCommitment: commitments.BytesList(),
		chainCodeCommitment:   bytes.Clone(chainCodeCommit),
	}
}

func (s frostKeygenProofStatement) domain() []byte {
	t := transcript.New(frostKeygenProofDomainLabel)
	t.AppendString("ciphersuite_context", s.ciphersuite)
	t.AppendString("protocol", string(s.protocol))
	t.AppendUint32("version", uint32(s.version))
	t.AppendBytes("session_id", s.sessionID[:])
	t.AppendUint32("round", uint32(s.round))
	t.AppendUint32("dealer", s.dealer)
	t.AppendUint32("threshold", uint32(s.threshold))
	t.AppendUint32List("parties", tss.SortParties(s.parties))
	t.AppendBytes("plan_hash", s.planHash)
	t.AppendBytesList("coefficient_commitments", s.coefficientCommitment)
	t.AppendBytes("chain_code_commitment", s.chainCodeCommitment)
	return t.Sum()
}

func marshalFROSTKeygenProof(proof *schnorred25519.Proof) ([]byte, error) {
	if proof == nil {
		return nil, errors.New("missing keygen constant-term proof")
	}
	encoded, err := proof.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal keygen constant-term proof: %w", err)
	}
	return encoded, nil
}

func equalFROSTKeygenProof(a, b *schnorred25519.Proof) bool {
	return a != nil && b != nil && bytes.Equal(a.Commitment, b.Commitment) && bytes.Equal(a.Response, b.Response)
}
