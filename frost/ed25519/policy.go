package ed25519

import "github.com/islishude/tss"

// FROSTPolicies defines the delivery policy matrix for the FROST Ed25519 protocol.
// Every payload type that a handler may receive must be registered here.
// Unregistered payload types are rejected by EnvelopeGuard.
var FROSTPolicies = tss.MustNewPolicySet(
	// --- Keygen ---
	tss.DeliveryPolicy{
		Protocol:             tss.ProtocolFROSTEd25519,
		Round:                1,
		PayloadType:          payloadKeygenCommitments,
		Mode:                 tss.DeliveryBroadcast,
		Confidentiality:      tss.ConfidentialityForbidden,
		BroadcastConsistency: tss.BroadcastConsistencyRequired,
	},
	tss.DeliveryPolicy{
		Protocol:             tss.ProtocolFROSTEd25519,
		Round:                1,
		PayloadType:          payloadKeygenShare,
		Mode:                 tss.DeliveryDirect,
		Confidentiality:      tss.ConfidentialityRequired,
		BroadcastConsistency: tss.BroadcastConsistencyNone,
	},
	tss.DeliveryPolicy{
		Protocol:             tss.ProtocolFROSTEd25519,
		Round:                2,
		PayloadType:          payloadKeygenConfirmation,
		Mode:                 tss.DeliveryBroadcast,
		Confidentiality:      tss.ConfidentialityForbidden,
		BroadcastConsistency: tss.BroadcastConsistencyNone,
	},

	// --- Sign ---
	tss.DeliveryPolicy{
		Protocol:             tss.ProtocolFROSTEd25519,
		Round:                1,
		PayloadType:          payloadSignCommitment,
		Mode:                 tss.DeliveryBroadcast,
		Confidentiality:      tss.ConfidentialityForbidden,
		BroadcastConsistency: tss.BroadcastConsistencyNone,
	},
	tss.DeliveryPolicy{
		Protocol:             tss.ProtocolFROSTEd25519,
		Round:                2,
		PayloadType:          payloadSignPartial,
		Mode:                 tss.DeliveryBroadcast,
		Confidentiality:      tss.ConfidentialityForbidden,
		BroadcastConsistency: tss.BroadcastConsistencyNone,
	},

	// --- Reshare ---
	tss.DeliveryPolicy{
		Protocol:             tss.ProtocolFROSTEd25519,
		Round:                1,
		PayloadType:          payloadReshareCommitments,
		Mode:                 tss.DeliveryBroadcast,
		Confidentiality:      tss.ConfidentialityForbidden,
		BroadcastConsistency: tss.BroadcastConsistencyRequired,
	},
	tss.DeliveryPolicy{
		Protocol:             tss.ProtocolFROSTEd25519,
		Round:                1,
		PayloadType:          payloadReshareShare,
		Mode:                 tss.DeliveryDirect,
		Confidentiality:      tss.ConfidentialityRequired,
		BroadcastConsistency: tss.BroadcastConsistencyNone,
	},
	// FROST reshare confirmations use payloadKeygenConfirmation (already registered)
)
