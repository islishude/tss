package ed25519

import "github.com/islishude/tss"

// frostPolicies defines the delivery policy matrix for the FROST Ed25519 protocol.
// Every payload type that a handler may receive must be registered here.
// Unregistered payload types are rejected by EnvelopeGuard.
//
// Confidentiality: messages containing secret shares (keygen shares, reshare shares)
// require ConfidentialityRequired. All other broadcast payloads use
// ConfidentialityOptional — they contain public commitments or partial signatures
// that do not require transport encryption but tolerate it (e.g. TLS/mTLS).
var frostPolicies = tss.MustNewPolicySet(
	// --- Keygen ---
	tss.DeliveryPolicy{
		Protocol:             tss.ProtocolFROSTEd25519,
		Round:                1,
		PayloadType:          payloadKeygenCommitments,
		Mode:                 tss.DeliveryBroadcast,
		Confidentiality:      tss.ConfidentialityOptional,
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
		Confidentiality:      tss.ConfidentialityOptional,
		BroadcastConsistency: tss.BroadcastConsistencyRequired,
	},

	// --- Sign ---
	tss.DeliveryPolicy{
		Protocol:             tss.ProtocolFROSTEd25519,
		Round:                1,
		PayloadType:          payloadSignCommitment,
		Mode:                 tss.DeliveryBroadcast,
		Confidentiality:      tss.ConfidentialityOptional,
		BroadcastConsistency: tss.BroadcastConsistencyRequired,
	},
	tss.DeliveryPolicy{
		Protocol:             tss.ProtocolFROSTEd25519,
		Round:                2,
		PayloadType:          payloadSignPartial,
		Mode:                 tss.DeliveryBroadcast,
		Confidentiality:      tss.ConfidentialityOptional,
		BroadcastConsistency: tss.BroadcastConsistencyRequired,
	},

	// --- Reshare ---
	tss.DeliveryPolicy{
		Protocol:             tss.ProtocolFROSTEd25519,
		Round:                1,
		PayloadType:          payloadReshareCommitments,
		Mode:                 tss.DeliveryBroadcast,
		Confidentiality:      tss.ConfidentialityOptional,
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
)

// FROSTPolicies returns the read-only delivery policy set for the FROST Ed25519
// protocol. The returned value is safe to pass to guard constructors and
// [tss.PolicySet.Entries] returns a copy — callers cannot mutate the original.
func FROSTPolicies() tss.PolicySet {
	return frostPolicies
}
