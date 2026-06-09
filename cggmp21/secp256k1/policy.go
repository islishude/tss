package secp256k1

import "github.com/islishude/tss"

// CGGMP21Policies defines the delivery policy matrix for the CGGMP21 secp256k1 protocol.
// Every payload type that a handler may receive must be registered here.
// Unregistered payload types are rejected by EnvelopeGuard.
//
// Confidentiality: messages containing secret shares (keygen shares, presign round2,
// refresh shares, reshare shares) require ConfidentialityRequired. All other broadcast
// payloads use ConfidentialityOptional — they contain public commitments, ciphertexts,
// or public-key material that does not require transport encryption but tolerates it
// (e.g. TLS/mTLS).
var CGGMP21Policies = tss.MustNewPolicySet(
	// --- Keygen ---
	tss.DeliveryPolicy{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		Round:                1,
		PayloadType:          payloadKeygenCommitments,
		Mode:                 tss.DeliveryBroadcast,
		Confidentiality:      tss.ConfidentialityOptional,
		BroadcastConsistency: tss.BroadcastConsistencyRequired,
	},
	tss.DeliveryPolicy{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		Round:                1,
		PayloadType:          payloadKeygenShare,
		Mode:                 tss.DeliveryDirect,
		Confidentiality:      tss.ConfidentialityRequired,
		BroadcastConsistency: tss.BroadcastConsistencyNone,
	},
	tss.DeliveryPolicy{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		Round:                2,
		PayloadType:          payloadKeygenConfirmation,
		Mode:                 tss.DeliveryBroadcast,
		Confidentiality:      tss.ConfidentialityOptional,
		BroadcastConsistency: tss.BroadcastConsistencyNone,
	},

	// --- Presign ---
	tss.DeliveryPolicy{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		Round:                1,
		PayloadType:          payloadPresignRound1,
		Mode:                 tss.DeliveryBroadcast,
		Confidentiality:      tss.ConfidentialityOptional,
		BroadcastConsistency: tss.BroadcastConsistencyNone,
	},
	tss.DeliveryPolicy{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		Round:                1,
		PayloadType:          payloadPresignRound1Proof,
		Mode:                 tss.DeliveryDirect,
		Confidentiality:      tss.ConfidentialityRequired,
		BroadcastConsistency: tss.BroadcastConsistencyNone,
	},
	tss.DeliveryPolicy{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		Round:                2,
		PayloadType:          payloadPresignRound2,
		Mode:                 tss.DeliveryDirect,
		Confidentiality:      tss.ConfidentialityRequired,
		BroadcastConsistency: tss.BroadcastConsistencyNone,
	},
	tss.DeliveryPolicy{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		Round:                3,
		PayloadType:          payloadPresignRound3,
		Mode:                 tss.DeliveryBroadcast,
		Confidentiality:      tss.ConfidentialityOptional,
		BroadcastConsistency: tss.BroadcastConsistencyNone,
	},

	// --- Sign ---
	tss.DeliveryPolicy{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		Round:                1,
		PayloadType:          payloadSignPartial,
		Mode:                 tss.DeliveryBroadcast,
		Confidentiality:      tss.ConfidentialityRequired,
		BroadcastConsistency: tss.BroadcastConsistencyNone,
	},

	// --- Refresh ---
	tss.DeliveryPolicy{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		Round:                1,
		PayloadType:          payloadRefreshCommitments,
		Mode:                 tss.DeliveryBroadcast,
		Confidentiality:      tss.ConfidentialityOptional,
		BroadcastConsistency: tss.BroadcastConsistencyRequired,
	},
	tss.DeliveryPolicy{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		Round:                1,
		PayloadType:          payloadRefreshShare,
		Mode:                 tss.DeliveryDirect,
		Confidentiality:      tss.ConfidentialityRequired,
		BroadcastConsistency: tss.BroadcastConsistencyNone,
	},
	// Refresh round 2 uses payloadKeygenConfirmation (already registered in keygen section)

	// --- Reshare ---
	tss.DeliveryPolicy{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		Round:                1,
		PayloadType:          payloadReshareDealerCommitments,
		Mode:                 tss.DeliveryBroadcast,
		Confidentiality:      tss.ConfidentialityOptional,
		BroadcastConsistency: tss.BroadcastConsistencyRequired,
	},
	tss.DeliveryPolicy{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		Round:                1,
		PayloadType:          payloadReshareShare,
		Mode:                 tss.DeliveryDirect,
		Confidentiality:      tss.ConfidentialityRequired,
		BroadcastConsistency: tss.BroadcastConsistencyNone,
	},
	tss.DeliveryPolicy{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		Round:                1,
		PayloadType:          payloadReshareReceiverMaterial,
		Mode:                 tss.DeliveryBroadcast,
		Confidentiality:      tss.ConfidentialityOptional,
		BroadcastConsistency: tss.BroadcastConsistencyNone,
	},
	// Reshare round 2 uses payloadKeygenConfirmation (already registered in keygen section)
)
