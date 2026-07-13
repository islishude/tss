package secp256k1

import "github.com/islishude/tss"

// cggmp21Policies defines the delivery policy matrix for the CGGMP21 secp256k1 protocol.
// Every payload type that a handler may receive must be registered here.
// Unregistered payload types are rejected by EnvelopeGuard.
//
// Confidentiality: messages containing secret shares (keygen shares, presign round2,
// refresh shares, reshare shares) require ConfidentialityRequired. All other broadcast
// payloads use ConfidentialityOptional — they contain public commitments, ciphertexts,
// or public-key material that does not require transport encryption but tolerates it
// (e.g. TLS/mTLS).
var cggmp21Policies = tss.MustNewPolicySet(
	// --- Keygen ---
	tss.DeliveryPolicy{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		Round:                keygenFigure6CommitmentRound,
		PayloadType:          payloadFigure6Commitment,
		Mode:                 tss.DeliveryBroadcast,
		Confidentiality:      tss.ConfidentialityOptional,
		BroadcastConsistency: tss.BroadcastConsistencyRequired,
	},
	tss.DeliveryPolicy{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		Round:                keygenFigure6RevealRound,
		PayloadType:          payloadFigure6Reveal,
		Mode:                 tss.DeliveryBroadcast,
		Confidentiality:      tss.ConfidentialityOptional,
		BroadcastConsistency: tss.BroadcastConsistencyRequired,
	},
	tss.DeliveryPolicy{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		Round:                keygenFigure6ProofRound,
		PayloadType:          payloadFigure6Proof,
		Mode:                 tss.DeliveryBroadcast,
		Confidentiality:      tss.ConfidentialityOptional,
		BroadcastConsistency: tss.BroadcastConsistencyRequired,
	},
	tss.DeliveryPolicy{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		Round:                keygenAuxInfoCommitmentRound,
		PayloadType:          payloadAuxInfoCommitment,
		Mode:                 tss.DeliveryBroadcast,
		Confidentiality:      tss.ConfidentialityOptional,
		BroadcastConsistency: tss.BroadcastConsistencyRequired,
	},
	tss.DeliveryPolicy{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		Round:                keygenAuxInfoRevealRound,
		PayloadType:          payloadAuxInfoReveal,
		Mode:                 tss.DeliveryBroadcast,
		Confidentiality:      tss.ConfidentialityOptional,
		BroadcastConsistency: tss.BroadcastConsistencyRequired,
	},
	tss.DeliveryPolicy{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		Round:                keygenAuxInfoProofRound,
		PayloadType:          payloadAuxInfoProofs,
		Mode:                 tss.DeliveryBroadcast,
		Confidentiality:      tss.ConfidentialityOptional,
		BroadcastConsistency: tss.BroadcastConsistencyRequired,
	},
	tss.DeliveryPolicy{
		Protocol:               tss.ProtocolCGGMP21Secp256k1,
		Round:                  keygenAuxInfoProofRound,
		PayloadType:            payloadAuxInfoDirect,
		Mode:                   tss.DeliveryDirect,
		Confidentiality:        tss.ConfidentialityRequired,
		BroadcastConsistency:   tss.BroadcastConsistencyNone,
		RequireSenderSignature: true,
	},
	tss.DeliveryPolicy{
		Protocol:               tss.ProtocolCGGMP21Secp256k1,
		Round:                  keygenAuxInfoProofRound,
		PayloadType:            payloadAuxInfoDecryptionError,
		Mode:                   tss.DeliveryBroadcast,
		Confidentiality:        tss.ConfidentialityOptional,
		BroadcastConsistency:   tss.BroadcastConsistencyRequired,
		RequireSenderSignature: true,
	},
	tss.DeliveryPolicy{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		Round:                keygenPaperConfirmationRound,
		PayloadType:          payloadKeygenConfirmation,
		Mode:                 tss.DeliveryBroadcast,
		Confidentiality:      tss.ConfidentialityOptional,
		BroadcastConsistency: tss.BroadcastConsistencyRequired,
	},

	// --- Presign ---
	tss.DeliveryPolicy{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		Round:                presignStartRound,
		PayloadType:          payloadPresignRound1,
		Mode:                 tss.DeliveryBroadcast,
		Confidentiality:      tss.ConfidentialityOptional,
		BroadcastConsistency: tss.BroadcastConsistencyRequired,
	},
	tss.DeliveryPolicy{
		Protocol:               tss.ProtocolCGGMP21Secp256k1,
		Round:                  presignStartRound,
		PayloadType:            payloadPresignRound1Proof,
		Mode:                   tss.DeliveryDirect,
		Confidentiality:        tss.ConfidentialityRequired,
		BroadcastConsistency:   tss.BroadcastConsistencyNone,
		RequireSenderSignature: true,
	},
	tss.DeliveryPolicy{
		Protocol:               tss.ProtocolCGGMP21Secp256k1,
		Round:                  presignRound2,
		PayloadType:            payloadPresignRound2,
		Mode:                   tss.DeliveryDirect,
		Confidentiality:        tss.ConfidentialityRequired,
		BroadcastConsistency:   tss.BroadcastConsistencyNone,
		RequireSenderSignature: true,
	},
	tss.DeliveryPolicy{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		Round:                presignRound3,
		PayloadType:          payloadPresignRound3,
		Mode:                 tss.DeliveryBroadcast,
		Confidentiality:      tss.ConfidentialityOptional,
		BroadcastConsistency: tss.BroadcastConsistencyRequired,
	},
	tss.DeliveryPolicy{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		Round:                presignRedAlertRound,
		PayloadType:          payloadPresignRedAlert,
		Mode:                 tss.DeliveryBroadcast,
		Confidentiality:      tss.ConfidentialityOptional,
		BroadcastConsistency: tss.BroadcastConsistencyRequired,
	},

	// --- Sign ---
	tss.DeliveryPolicy{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		Round:                signStartRound,
		PayloadType:          payloadSignPartial,
		Mode:                 tss.DeliveryBroadcast,
		Confidentiality:      tss.ConfidentialityRequired,
		BroadcastConsistency: tss.BroadcastConsistencyRequired,
	},
	// --- Refresh ---
	tss.DeliveryPolicy{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		Round:                refreshAuxInfoCommitmentRound,
		PayloadType:          payloadAuxInfoCommitment,
		Mode:                 tss.DeliveryBroadcast,
		Confidentiality:      tss.ConfidentialityOptional,
		BroadcastConsistency: tss.BroadcastConsistencyRequired,
	},
	tss.DeliveryPolicy{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		Round:                refreshAuxInfoRevealRound,
		PayloadType:          payloadAuxInfoReveal,
		Mode:                 tss.DeliveryBroadcast,
		Confidentiality:      tss.ConfidentialityOptional,
		BroadcastConsistency: tss.BroadcastConsistencyRequired,
	},
	tss.DeliveryPolicy{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		Round:                refreshAuxInfoProofRound,
		PayloadType:          payloadAuxInfoProofs,
		Mode:                 tss.DeliveryBroadcast,
		Confidentiality:      tss.ConfidentialityOptional,
		BroadcastConsistency: tss.BroadcastConsistencyRequired,
	},
	tss.DeliveryPolicy{
		Protocol:               tss.ProtocolCGGMP21Secp256k1,
		Round:                  refreshAuxInfoProofRound,
		PayloadType:            payloadAuxInfoDirect,
		Mode:                   tss.DeliveryDirect,
		Confidentiality:        tss.ConfidentialityRequired,
		BroadcastConsistency:   tss.BroadcastConsistencyNone,
		RequireSenderSignature: true,
	},
	tss.DeliveryPolicy{
		Protocol:               tss.ProtocolCGGMP21Secp256k1,
		Round:                  refreshAuxInfoProofRound,
		PayloadType:            payloadAuxInfoDecryptionError,
		Mode:                   tss.DeliveryBroadcast,
		Confidentiality:        tss.ConfidentialityOptional,
		BroadcastConsistency:   tss.BroadcastConsistencyRequired,
		RequireSenderSignature: true,
	},
	tss.DeliveryPolicy{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		Round:                refreshConfirmationRound,
		PayloadType:          payloadKeygenConfirmation,
		Mode:                 tss.DeliveryBroadcast,
		Confidentiality:      tss.ConfidentialityOptional,
		BroadcastConsistency: tss.BroadcastConsistencyRequired,
	},
	// --- Child derivation ---
	// Figure 7 uses the same round numbers and payload policies as refresh.
	// The final confirmation has a distinct payload type so lifecycle intent
	// cannot be confused even when a transport routes by protocol and round.
	tss.DeliveryPolicy{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		Round:                childConfirmationRound,
		PayloadType:          payloadChildConfirmation,
		Mode:                 tss.DeliveryBroadcast,
		Confidentiality:      tss.ConfidentialityOptional,
		BroadcastConsistency: tss.BroadcastConsistencyRequired,
	},
	// --- Reshare ---
	tss.DeliveryPolicy{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		Round:                reshareStartRound,
		PayloadType:          payloadReshareDealerCommitments,
		Mode:                 tss.DeliveryBroadcast,
		Confidentiality:      tss.ConfidentialityOptional,
		BroadcastConsistency: tss.BroadcastConsistencyRequired,
	},
	tss.DeliveryPolicy{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		Round:                reshareAuxInfoCommitmentRound,
		PayloadType:          payloadAuxInfoCommitment,
		Mode:                 tss.DeliveryBroadcast,
		Confidentiality:      tss.ConfidentialityOptional,
		BroadcastConsistency: tss.BroadcastConsistencyRequired,
	},
	tss.DeliveryPolicy{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		Round:                reshareAuxInfoRevealRound,
		PayloadType:          payloadAuxInfoReveal,
		Mode:                 tss.DeliveryBroadcast,
		Confidentiality:      tss.ConfidentialityOptional,
		BroadcastConsistency: tss.BroadcastConsistencyRequired,
	},
	tss.DeliveryPolicy{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		Round:                reshareAuxInfoProofRound,
		PayloadType:          payloadAuxInfoProofs,
		Mode:                 tss.DeliveryBroadcast,
		Confidentiality:      tss.ConfidentialityOptional,
		BroadcastConsistency: tss.BroadcastConsistencyRequired,
	},
	tss.DeliveryPolicy{
		Protocol:               tss.ProtocolCGGMP21Secp256k1,
		Round:                  reshareAuxInfoProofRound,
		PayloadType:            payloadAuxInfoDirect,
		Mode:                   tss.DeliveryDirect,
		Confidentiality:        tss.ConfidentialityRequired,
		BroadcastConsistency:   tss.BroadcastConsistencyNone,
		RequireSenderSignature: true,
	},
	tss.DeliveryPolicy{
		Protocol:               tss.ProtocolCGGMP21Secp256k1,
		Round:                  reshareAuxInfoProofRound,
		PayloadType:            payloadAuxInfoDecryptionError,
		Mode:                   tss.DeliveryBroadcast,
		Confidentiality:        tss.ConfidentialityOptional,
		BroadcastConsistency:   tss.BroadcastConsistencyRequired,
		RequireSenderSignature: true,
	},
	tss.DeliveryPolicy{
		Protocol:               tss.ProtocolCGGMP21Secp256k1,
		Round:                  reshareShareRound,
		PayloadType:            payloadReshareFactorProof,
		Mode:                   tss.DeliveryDirect,
		Confidentiality:        tss.ConfidentialityOptional,
		BroadcastConsistency:   tss.BroadcastConsistencyNone,
		RequireSenderSignature: true,
	},
	tss.DeliveryPolicy{
		Protocol:               tss.ProtocolCGGMP21Secp256k1,
		Round:                  reshareShareRound,
		PayloadType:            payloadReshareShare,
		Mode:                   tss.DeliveryDirect,
		Confidentiality:        tss.ConfidentialityRequired,
		BroadcastConsistency:   tss.BroadcastConsistencyNone,
		RequireSenderSignature: true,
	},
	tss.DeliveryPolicy{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		Round:                reshareStartRound,
		PayloadType:          payloadReshareReceiverMaterial,
		Mode:                 tss.DeliveryBroadcast,
		Confidentiality:      tss.ConfidentialityOptional,
		BroadcastConsistency: tss.BroadcastConsistencyRequired,
	},
	tss.DeliveryPolicy{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		Round:                reshareConfirmationRound,
		PayloadType:          payloadKeygenConfirmation,
		Mode:                 tss.DeliveryBroadcast,
		Confidentiality:      tss.ConfidentialityOptional,
		BroadcastConsistency: tss.BroadcastConsistencyRequired,
	},
)

// CGGMP21Policies returns the read-only delivery policy set for the CGGMP21
// secp256k1 protocol. The returned value is safe to pass to guard constructors
// and [tss.PolicySet.Entries] returns a copy — callers cannot mutate the original.
func CGGMP21Policies() tss.PolicySet {
	return cggmp21Policies
}
