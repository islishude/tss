// Package tss defines transport-neutral building blocks shared by the
// threshold-signature protocol packages in this module.
//
// The root package intentionally does not provide a network transport, durable
// storage, or secret-at-rest encryption. Callers are responsible for authenticated
// delivery of envelopes and must construct [InboundEnvelope] values with
// [OpenEnvelope] and transport-verified [ReceiveInfo]. Confidentiality
// requirements are defined per payload type by the protocol [PolicySet] and
// enforced by [EnvelopeGuard].
//
// # Security Model
//
// Every protocol session must receive an [EnvelopeGuard] at its Start* entry
// point before it can emit or process protocol envelopes. The guard enforces:
//   - transport authentication ([ReceiveInfo.Peer])
//   - sender identity binding (ReceiveInfo.Peer == Envelope.From)
//   - confidentiality per protocol policy ([DeliveryPolicy.Confidentiality])
//   - broadcast consistency via [BroadcastCertificate] where required
//   - replay detection via [ReplayCache]
//
// Sessions reject startup and inbound handling when no guard is configured.
// Production integrations must construct a guard via [NewEnvelopeGuard] or
// [GuardConfig.BuildGuard] with a production [PolicySet] and a durable
// [ReplayCache].
//
// See docs/security.md for the complete threat model and integration checklist.
package tss
