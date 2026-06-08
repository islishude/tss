// Package tss defines transport-neutral building blocks shared by the
// threshold-signature protocol packages in this module.
//
// The root package intentionally does not provide a network transport, durable
// storage, or secret-at-rest encryption. Callers are responsible for authenticated
// delivery of envelopes and must set [Envelope.Security] via the transport
// receive path. Confidentiality requirements are defined per payload type by
// the protocol [PolicySet] and enforced by [EnvelopeGuard].
//
// # Security Model
//
// Every protocol session must hold an [EnvelopeGuard], attached via SetGuard
// before processing any inbound envelopes. The guard enforces:
//   - transport authentication ([SecurityContext.Authenticated])
//   - sender identity binding (AuthenticatedParty == Envelope.From)
//   - confidentiality per protocol policy ([DeliveryPolicy.Confidentiality])
//   - broadcast consistency via [BroadcastCertificate] where required
//   - replay detection via [ReplayCache]
//
// Sessions reject authenticated transport envelopes when no guard is
// configured. Production integrations must construct a guard via
// [NewEnvelopeGuard] or [GuardConfig.BuildGuard] with a production
// [PolicySet] and a durable [ReplayCache].
//
// See docs/security.md for the complete threat model and integration checklist.
package tss
