package secp256k1

import (
	"github.com/islishude/tss"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/transcript"
)

const (
	proofDomainVersion = "cggmp21-secp256k1-proof-domain-v1"

	// Domain labels identify the protocol phase for domain separation.
	domainLabelKeygenModulus        = "keygen.modulus"
	domainLabelKeygenRingPedersen   = "keygen.ring-pedersen"
	domainLabelKeySharePaillier     = "keyshare.paillier-modulus"
	domainLabelPresignMTAStartProof = "presign.mta-start.enc-proof"
	domainLabelPresignMTADelta      = "presign.mta-response.delta"
	domainLabelPresignMTASigma      = "presign.mta-response.sigma"
	domainLabelResharePaillier      = "reshare.paillier-modulus"
	domainLabelReshareRingPedersen  = "reshare.ring-pedersen"
	domainLabelRefreshPaillier      = "refresh.paillier-modulus"
	domainLabelRefreshRingPedersen  = "refresh.ring-pedersen"
	domainLabelKeyShareLogProof     = "keyshare.log-proof"
	domainLabelReshareLogProof      = "reshare.log-proof"
	domainLabelRefreshLogProof      = "refresh.log-proof"
)

type proofDomainContext struct {
	label              string
	sessionID          tss.SessionID
	threshold          int
	parties            []tss.PartyID
	signers            []tss.PartyID
	sender             tss.PartyID
	receiver           tss.PartyID
	statementPublicKey []byte
	keyTranscriptHash  []byte
	paillierPublicKey  []byte
	ringPedersenParams []byte
	presignContextHash []byte
	lifecyclePlanHash  []byte
}

func keygenModulusDomain(config tss.ThresholdConfig, sender tss.PartyID, paillierPublicKey, planHash []byte) []byte {
	return proofDomain(proofDomainContext{
		label:             domainLabelKeygenModulus,
		sessionID:         config.SessionID,
		threshold:         config.Threshold,
		parties:           config.Parties,
		sender:            sender,
		paillierPublicKey: paillierPublicKey,
		lifecyclePlanHash: planHash,
	})
}

func keygenRingPedersenDomain(config tss.ThresholdConfig, sender tss.PartyID, params, planHash []byte) []byte {
	return proofDomain(proofDomainContext{
		label:              domainLabelKeygenRingPedersen,
		sessionID:          config.SessionID,
		threshold:          config.Threshold,
		parties:            config.Parties,
		sender:             sender,
		ringPedersenParams: params,
		lifecyclePlanHash:  planHash,
	})
}

func keySharePaillierProofDomain(key *KeyShare) []byte {
	if key == nil {
		return nil
	}
	return proofDomain(proofDomainContext{
		label:              domainLabelKeySharePaillier,
		threshold:          key.state.threshold,
		parties:            key.state.parties,
		sender:             key.state.party,
		statementPublicKey: key.state.publicKey,
		keyTranscriptHash:  key.state.keygenTranscriptHash,
		paillierPublicKey:  key.state.paillierPublicKey,
		lifecyclePlanHash:  key.state.planHash,
	})
}

func keyShareRingPedersenProofDomain(key *KeyShare, party tss.PartyID, params []byte) []byte {
	if key == nil {
		return nil
	}
	config := tss.ThresholdConfig{
		Threshold: key.state.threshold,
		Parties:   key.state.parties,
		Self:      party,
		SessionID: key.state.paillierProofSessionID,
	}
	switch key.state.paillierProofDomain {
	case domainLabelKeygenModulus:
		return keygenRingPedersenDomain(config, party, params, key.state.planHash)
	case domainLabelRefreshPaillier:
		return refreshRingPedersenDomain(config, party, params, key.state.planHash)
	case domainLabelResharePaillier:
		return reshareRingPedersenDomain(config, party, params, key.state.planHash)
	default:
		return nil
	}
}

func mtaStartProofDomain(key *KeyShare, sessionID tss.SessionID, signers []tss.PartyID, prover, verifier tss.PartyID, proverPaillierPublicKey, presignContextHash, planHash []byte) []byte {
	return proofDomain(proofDomainContext{
		label:              domainLabelPresignMTAStartProof,
		sessionID:          sessionID,
		threshold:          key.state.threshold,
		parties:            key.state.parties,
		signers:            signers,
		sender:             prover,
		receiver:           verifier,
		statementPublicKey: key.state.publicKey,
		keyTranscriptHash:  key.state.keygenTranscriptHash,
		paillierPublicKey:  proverPaillierPublicKey,
		presignContextHash: presignContextHash,
		lifecyclePlanHash:  planHash,
	})
}

func resharePaillierDomain(config tss.ThresholdConfig, sender tss.PartyID, paillierPublicKey, planHash []byte) []byte {
	return proofDomain(proofDomainContext{
		label:             domainLabelResharePaillier,
		sessionID:         config.SessionID,
		threshold:         config.Threshold,
		parties:           config.Parties,
		sender:            sender,
		paillierPublicKey: paillierPublicKey,
		lifecyclePlanHash: planHash,
	})
}

func reshareRingPedersenDomain(config tss.ThresholdConfig, sender tss.PartyID, params, planHash []byte) []byte {
	return proofDomain(proofDomainContext{
		label:              domainLabelReshareRingPedersen,
		sessionID:          config.SessionID,
		threshold:          config.Threshold,
		parties:            config.Parties,
		sender:             sender,
		ringPedersenParams: params,
		lifecyclePlanHash:  planHash,
	})
}

func refreshPaillierDomain(config tss.ThresholdConfig, sender tss.PartyID, paillierPublicKey, planHash []byte) []byte {
	return proofDomain(proofDomainContext{
		label:             domainLabelRefreshPaillier,
		sessionID:         config.SessionID,
		threshold:         config.Threshold,
		parties:           config.Parties,
		sender:            sender,
		paillierPublicKey: paillierPublicKey,
		lifecyclePlanHash: planHash,
	})
}

func refreshRingPedersenDomain(config tss.ThresholdConfig, sender tss.PartyID, params, planHash []byte) []byte {
	return proofDomain(proofDomainContext{
		label:              domainLabelRefreshRingPedersen,
		sessionID:          config.SessionID,
		threshold:          config.Threshold,
		parties:            config.Parties,
		sender:             sender,
		ringPedersenParams: params,
		lifecyclePlanHash:  planHash,
	})
}

func mtaDeltaResponseDomain(key *KeyShare, sessionID tss.SessionID, signers []tss.PartyID, initiator, responder tss.PartyID, initiatorPaillierPublicKey, presignContextHash, planHash []byte) []byte {
	return mtaResponseDomain(domainLabelPresignMTADelta, key, sessionID, signers, initiator, responder, initiatorPaillierPublicKey, presignContextHash, planHash)
}

func mtaSigmaResponseDomain(key *KeyShare, sessionID tss.SessionID, signers []tss.PartyID, initiator, responder tss.PartyID, initiatorPaillierPublicKey, presignContextHash, planHash []byte) []byte {
	return mtaResponseDomain(domainLabelPresignMTASigma, key, sessionID, signers, initiator, responder, initiatorPaillierPublicKey, presignContextHash, planHash)
}

func mtaResponseDomain(label string, key *KeyShare, sessionID tss.SessionID, signers []tss.PartyID, initiator, responder tss.PartyID, initiatorPaillierPublicKey, presignContextHash, planHash []byte) []byte {
	return proofDomain(proofDomainContext{
		label:              label,
		sessionID:          sessionID,
		threshold:          key.state.threshold,
		parties:            key.state.parties,
		signers:            signers,
		sender:             responder,
		receiver:           initiator,
		statementPublicKey: key.state.publicKey,
		keyTranscriptHash:  key.state.keygenTranscriptHash,
		paillierPublicKey:  initiatorPaillierPublicKey,
		presignContextHash: presignContextHash,
		lifecyclePlanHash:  planHash,
	})
}

func logProofDomain(key *KeyShare, pk *pai.PublicKey, verificationShare, transcriptHash []byte) []byte {
	if key == nil || pk == nil {
		return nil
	}
	label := domainLabelKeyShareLogProof
	switch key.state.paillierProofDomain {
	case domainLabelResharePaillier:
		label = domainLabelReshareLogProof
	case domainLabelRefreshPaillier:
		label = domainLabelRefreshLogProof
	}
	// MarshalBinary cannot fail for a validated or freshly-generated PublicKey;
	// callers must ensure pk passes pai.UnmarshalPublicKey or pai.GenerateKey first.
	pkBytes, _ := pk.MarshalBinary()
	return proofDomain(proofDomainContext{
		label:              label,
		sessionID:          key.state.paillierProofSessionID,
		threshold:          key.state.threshold,
		parties:            key.state.parties,
		sender:             key.state.party,
		statementPublicKey: verificationShare,
		keyTranscriptHash:  transcriptHash,
		paillierPublicKey:  pkBytes,
		lifecyclePlanHash:  key.state.planHash,
	})
}

func proofDomain(ctx proofDomainContext) []byte {
	t := transcript.New(proofDomainVersion)
	t.AppendString("protocol", string(protocol))
	t.AppendUint32("version", uint32(tss.Version))
	t.AppendString("proof_label", ctx.label)
	t.AppendBytes("session_id", ctx.sessionID[:])
	t.AppendUint32("threshold", uint32(ctx.threshold))
	t.AppendUint32List("parties", tss.SortParties(ctx.parties))
	t.AppendUint32List("signers", tss.SortParties(ctx.signers))
	t.AppendUint32("sender", ctx.sender)
	t.AppendUint32("receiver", ctx.receiver)
	t.AppendBytes("public_key", ctx.statementPublicKey)
	t.AppendBytes("keygen_transcript_hash", ctx.keyTranscriptHash)
	t.AppendBytes("paillier_public_key", ctx.paillierPublicKey)
	t.AppendBytes("ring_pedersen_params", ctx.ringPedersenParams)
	t.AppendBytes("presign_context_hash", ctx.presignContextHash)
	t.AppendBytes("lifecycle_plan_hash", ctx.lifecyclePlanHash)
	return t.Sum()
}
