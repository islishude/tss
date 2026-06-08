package secp256k1

import "github.com/islishude/tss"

// CGGMP21Policies defines the delivery policy matrix for the CGGMP21 secp256k1 protocol.
// Every payload type that a handler may receive must be registered here.
// Unregistered payload types are rejected by EnvelopeGuard.
var CGGMP21Policies = tss.PolicySet{
	// --- Keygen ---
	{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		Round:                1,
		PayloadType:          payloadKeygenCommitments,
		Mode:                 tss.DeliveryBroadcast,
		Confidentiality:      tss.ConfidentialityForbidden,
		BroadcastConsistency: tss.BroadcastConsistencyRequired,
	},
	{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		Round:                1,
		PayloadType:          payloadKeygenShare,
		Mode:                 tss.DeliveryDirect,
		Confidentiality:      tss.ConfidentialityRequired,
		BroadcastConsistency: tss.BroadcastConsistencyNone,
	},
	{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		Round:                2,
		PayloadType:          payloadKeygenConfirmation,
		Mode:                 tss.DeliveryBroadcast,
		Confidentiality:      tss.ConfidentialityForbidden,
		BroadcastConsistency: tss.BroadcastConsistencyNone,
	},

	// --- Presign ---
	{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		Round:                1,
		PayloadType:          payloadPresignRound1,
		Mode:                 tss.DeliveryBroadcast,
		Confidentiality:      tss.ConfidentialityForbidden,
		BroadcastConsistency: tss.BroadcastConsistencyNone,
	},
	{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		Round:                1,
		PayloadType:          payloadPresignRound1Proof,
		Mode:                 tss.DeliveryDirect,
		Confidentiality:      tss.ConfidentialityRequired,
		BroadcastConsistency: tss.BroadcastConsistencyNone,
	},
	{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		Round:                2,
		PayloadType:          payloadPresignRound2,
		Mode:                 tss.DeliveryDirect,
		Confidentiality:      tss.ConfidentialityRequired,
		BroadcastConsistency: tss.BroadcastConsistencyNone,
	},
	{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		Round:                3,
		PayloadType:          payloadPresignRound3,
		Mode:                 tss.DeliveryBroadcast,
		Confidentiality:      tss.ConfidentialityForbidden,
		BroadcastConsistency: tss.BroadcastConsistencyNone,
	},

	// --- Sign ---
	{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		Round:                1,
		PayloadType:          payloadSignPartial,
		Mode:                 tss.DeliveryBroadcast,
		Confidentiality:      tss.ConfidentialityRequired,
		BroadcastConsistency: tss.BroadcastConsistencyNone,
	},

	// --- Refresh ---
	{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		Round:                1,
		PayloadType:          payloadRefreshCommitments,
		Mode:                 tss.DeliveryBroadcast,
		Confidentiality:      tss.ConfidentialityForbidden,
		BroadcastConsistency: tss.BroadcastConsistencyRequired,
	},
	{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		Round:                1,
		PayloadType:          payloadRefreshShare,
		Mode:                 tss.DeliveryDirect,
		Confidentiality:      tss.ConfidentialityRequired,
		BroadcastConsistency: tss.BroadcastConsistencyNone,
	},
	// Refresh round 2 uses payloadKeygenConfirmation (already registered in keygen section)

	// --- Reshare ---
	{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		Round:                1,
		PayloadType:          payloadReshareDealerCommitments,
		Mode:                 tss.DeliveryBroadcast,
		Confidentiality:      tss.ConfidentialityForbidden,
		BroadcastConsistency: tss.BroadcastConsistencyRequired,
	},
	{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		Round:                1,
		PayloadType:          payloadReshareShare,
		Mode:                 tss.DeliveryDirect,
		Confidentiality:      tss.ConfidentialityRequired,
		BroadcastConsistency: tss.BroadcastConsistencyNone,
	},
	{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		Round:                1,
		PayloadType:          payloadReshareReceiverMaterial,
		Mode:                 tss.DeliveryBroadcast,
		Confidentiality:      tss.ConfidentialityForbidden,
		BroadcastConsistency: tss.BroadcastConsistencyNone,
	},
	// Reshare round 2 uses payloadKeygenConfirmation (already registered in keygen section)
}
