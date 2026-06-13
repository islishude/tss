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
	domainLabelPresignMTAResponse   = "presign.mta-response"
	domainLabelResharePaillier      = "reshare.paillier-modulus"
	domainLabelReshareRingPedersen  = "reshare.ring-pedersen"
	domainLabelRefreshPaillier      = "refresh.paillier-modulus"
	domainLabelRefreshRingPedersen  = "refresh.ring-pedersen"
	domainLabelKeyShareLogProof     = "keyshare.log-proof"
	domainLabelReshareLogProof      = "reshare.log-proof"
	domainLabelRefreshLogProof      = "refresh.log-proof"

	// Domain kinds identify the cryptographic object bound into a proof.
	domainKindPaillierModulus = "paillier-modulus"
	domainKindRingPedersen    = "ring-pedersen"
	domainKindEncProof        = "enc-proof"
	domainKindLogProof        = "log-proof"
)

type proofDomainContext struct {
	label                string
	sessionID            tss.SessionID
	threshold            int
	parties              []tss.PartyID
	signers              []tss.PartyID
	sender               tss.PartyID
	receiver             tss.PartyID
	kind                 string
	publicKey            []byte
	keygenTranscriptHash []byte
	paillierPublicKey    []byte
	ringPedersenParams   []byte
	presignContextHash   []byte
	resharePlanHash      []byte
}

func keygenModulusDomain(config tss.ThresholdConfig, sender tss.PartyID, paillierPublicKey []byte) []byte {
	return proofDomain(proofDomainContext{
		label:             domainLabelKeygenModulus,
		sessionID:         config.SessionID,
		threshold:         config.Threshold,
		parties:           config.Parties,
		sender:            sender,
		kind:              domainKindPaillierModulus,
		paillierPublicKey: paillierPublicKey,
	})
}

func keygenRingPedersenDomain(config tss.ThresholdConfig, sender tss.PartyID, params []byte) []byte {
	return proofDomain(proofDomainContext{
		label:              domainLabelKeygenRingPedersen,
		sessionID:          config.SessionID,
		threshold:          config.Threshold,
		parties:            config.Parties,
		sender:             sender,
		kind:               domainKindRingPedersen,
		ringPedersenParams: params,
	})
}

func keySharePaillierProofDomain(key *KeyShare) []byte {
	if key == nil {
		return nil
	}
	return proofDomain(proofDomainContext{
		label:                domainLabelKeySharePaillier,
		threshold:            key.state.threshold,
		parties:              key.state.parties,
		sender:               key.state.party,
		kind:                 domainKindPaillierModulus,
		publicKey:            key.state.publicKey,
		keygenTranscriptHash: key.state.keygenTranscriptHash,
		paillierPublicKey:    key.state.paillierPublicKey,
		resharePlanHash:      key.state.resharePlanHash,
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
		return keygenRingPedersenDomain(config, party, params)
	case domainLabelRefreshPaillier:
		return refreshRingPedersenDomain(config, party, params)
	case domainLabelResharePaillier:
		return reshareRingPedersenDomain(config, party, params, key.state.resharePlanHash)
	default:
		return nil
	}
}

func mtaStartProofDomain(key *KeyShare, sessionID tss.SessionID, signers []tss.PartyID, prover, verifier tss.PartyID, proverPaillierPublicKey, presignContextHash []byte) []byte {
	return proofDomain(proofDomainContext{
		label:                domainLabelPresignMTAStartProof,
		sessionID:            sessionID,
		threshold:            key.state.threshold,
		parties:              key.state.parties,
		signers:              signers,
		sender:               prover,
		receiver:             verifier,
		kind:                 domainKindEncProof,
		publicKey:            key.state.publicKey,
		keygenTranscriptHash: key.state.keygenTranscriptHash,
		paillierPublicKey:    proverPaillierPublicKey,
		presignContextHash:   presignContextHash,
	})
}

func resharePaillierDomain(config tss.ThresholdConfig, sender tss.PartyID, paillierPublicKey, planHash []byte) []byte {
	return proofDomain(proofDomainContext{
		label:             domainLabelResharePaillier,
		sessionID:         config.SessionID,
		threshold:         config.Threshold,
		parties:           config.Parties,
		sender:            sender,
		kind:              domainKindPaillierModulus,
		paillierPublicKey: paillierPublicKey,
		resharePlanHash:   planHash,
	})
}

func reshareRingPedersenDomain(config tss.ThresholdConfig, sender tss.PartyID, params, planHash []byte) []byte {
	return proofDomain(proofDomainContext{
		label:              domainLabelReshareRingPedersen,
		sessionID:          config.SessionID,
		threshold:          config.Threshold,
		parties:            config.Parties,
		sender:             sender,
		kind:               domainKindRingPedersen,
		ringPedersenParams: params,
		resharePlanHash:    planHash,
	})
}

func refreshPaillierDomain(config tss.ThresholdConfig, sender tss.PartyID, paillierPublicKey []byte) []byte {
	return proofDomain(proofDomainContext{
		label:             domainLabelRefreshPaillier,
		sessionID:         config.SessionID,
		threshold:         config.Threshold,
		parties:           config.Parties,
		sender:            sender,
		kind:              domainKindPaillierModulus,
		paillierPublicKey: paillierPublicKey,
	})
}

func refreshRingPedersenDomain(config tss.ThresholdConfig, sender tss.PartyID, params []byte) []byte {
	return proofDomain(proofDomainContext{
		label:              domainLabelRefreshRingPedersen,
		sessionID:          config.SessionID,
		threshold:          config.Threshold,
		parties:            config.Parties,
		sender:             sender,
		kind:               domainKindRingPedersen,
		ringPedersenParams: params,
	})
}

func mtaResponseDomain(key *KeyShare, sessionID tss.SessionID, signers []tss.PartyID, initiator, responder tss.PartyID, kind string, initiatorPaillierPublicKey, presignContextHash []byte) []byte {
	return proofDomain(proofDomainContext{
		label:                domainLabelPresignMTAResponse,
		sessionID:            sessionID,
		threshold:            key.state.threshold,
		parties:              key.state.parties,
		signers:              signers,
		sender:               responder,
		receiver:             initiator,
		kind:                 kind,
		publicKey:            key.state.publicKey,
		keygenTranscriptHash: key.state.keygenTranscriptHash,
		paillierPublicKey:    initiatorPaillierPublicKey,
		presignContextHash:   presignContextHash,
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
		label:                label,
		sessionID:            key.state.paillierProofSessionID,
		threshold:            key.state.threshold,
		parties:              key.state.parties,
		sender:               key.state.party,
		kind:                 domainKindLogProof,
		publicKey:            verificationShare, // verification share point binds this proof to the party's share
		keygenTranscriptHash: transcriptHash,
		paillierPublicKey:    pkBytes,
		resharePlanHash:      key.state.resharePlanHash,
	})
}

func proofDomain(ctx proofDomainContext) []byte {
	t := transcript.New(proofDomainVersion)
	t.AppendString("protocol", string(protocol))
	t.AppendUint32("version", uint32(tss.Version))
	t.AppendString("proof_label", ctx.label)
	t.AppendBytes("session_id", ctx.sessionID[:])
	t.AppendUint32("threshold", uint32(ctx.threshold))
	t.AppendUint32List("parties", transcript.Uint32s(tss.SortParties(ctx.parties)))
	t.AppendUint32List("signers", transcript.Uint32s(tss.SortParties(ctx.signers)))
	t.AppendUint32("sender", uint32(ctx.sender))
	t.AppendUint32("receiver", uint32(ctx.receiver))
	t.AppendString("proof_kind", ctx.kind)
	t.AppendBytes("public_key", ctx.publicKey)
	t.AppendBytes("keygen_transcript_hash", ctx.keygenTranscriptHash)
	t.AppendBytes("paillier_public_key", ctx.paillierPublicKey)
	t.AppendBytes("ring_pedersen_params", ctx.ringPedersenParams)
	t.AppendBytes("presign_context_hash", ctx.presignContextHash)
	t.AppendBytes("reshare_plan_hash", ctx.resharePlanHash)
	return t.Sum()
}
