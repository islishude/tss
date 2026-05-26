# Security Notes

This repository is not a production-audited TSS stack.

## Threat Model

The library assumes each local caller controls one honest party state machine and receives envelopes from an external authenticated transport. State machines reject malformed messages, wrong sessions, wrong rounds, duplicate messages, non-participants, invalid curve/scalar encodings, and failed proof checks.

The library does not protect against a transport that lies about sender identity, drops all messages, strips confidentiality, replays old traffic before the caller checks session ids, or leaks persisted key-share files.

## Caller Responsibilities

Callers must provide:

- authenticated peer identity for every envelope;
- encryption for envelopes with `ConfidentialRequired`;
- replay protection and session-id freshness;
- durable storage encryption for key shares and presigns;
- secure deletion or `Destroy` calls for no-longer-needed local shares;
- operational monitoring for protocol errors and blame evidence.

Never log secret scalar, nonce, Paillier private-key, key-share, or presign bytes. Blame evidence is designed to contain public hashes and public context only.

## Production Integration Checklist

Before passing an inbound envelope to any state machine, the caller must verify
that the authenticated transport identity for the peer exactly matches
`Envelope.From`. The library checks that `Envelope.From` is a participant or
signer where applicable, but it cannot know whether the transport authenticated
the same party id.

Every inbound envelope must include the transcript hash produced by
`Envelope.WithTranscriptHash`. `ValidateBasic` rejects missing or mismatched
transcript hashes before payload decoding, so callers should recompute the hash
after any relay, storage, or framing layer changes an envelope.

Session ids must be fresh, unpredictable, and scoped to one protocol run. A
completed or attributable-aborted session rejects later messages without
mutating local state; callers should stop routing messages to such sessions and
surface the original protocol error and blame evidence.

The repository intentionally leaves these integration pieces to callers:
network transport, peer authentication, storage encryption, secure deletion of
persisted records, retries, consensus over session creation, KMS/HSM policy,
and operational alerting.

## Secret-Material Lifecycle

Secret-bearing records reject default JSON marshaling. Persist `KeyShare` and
CGGMP21 `Presign` values only through their explicit binary encoders, then store
the resulting bytes under caller-managed encryption.

Call `Destroy` on key shares, presigns, keygen sessions, presign sessions, and
signing sessions once they are no longer needed. These methods clear local
secret byte slices and scalar state such as Shamir shares, nonces, online
partials, Paillier private factors, and CGGMP21 presign shares while leaving
public metadata, such as party ids, public keys, signer sets, transcript hashes,
and public signatures, available for diagnostics where practical.

Zeroization in Go is best-effort. The library clears owned byte slices and
overwrites currently referenced `big.Int` words, but Go's garbage collector,
compiler optimizations, stack copies, immutable prior encodings, and caller-made
copies can leave historical secret material elsewhere in process memory. Use
short process lifetimes, encrypted persistence, locked-down crash reporting, and
process isolation when stronger memory-erasure guarantees are required.

## CGGMP21 Status

`cggmp21/secp256k1` remains experimental. It avoids transmitting or reconstructing private shares and nonce shares during signing, checks that presign participants share the same round-1 broadcast view, supports caller-provided additive public-key shifts, and encodes Paillier/ZK proof payloads as canonical binary TLV records. The Paillier/ZK proof layer and identifiable-abort behavior still require independent cryptographic audit before production use.

Unsupported in v1:

- resharing;
- proactive refresh;
- BIP32/SLIP10 path derivation;
- network transport;
- storage encryption;
- full production-ready identifiable abort;
- external audit claims.

## One-Time Presigns

CGGMP21 presigns include nonce-derived local material. Reusing a presign can break ECDSA security. `StartSignDigest` sets `Presign.Consumed` before constructing any outbound online signing envelope so reuse fails before a second partial signature leaves the process.

## Blame Evidence

When a failure can be attributed, `ProtocolError.Blame` may include `Evidence`. Evidence binds protocol, session, round, sender, payload type, payload hash, transcript hash, reason, and selected public input hashes. Use `secp256k1.VerifyBlameEvidence` to validate CGGMP21 evidence against known public context.
