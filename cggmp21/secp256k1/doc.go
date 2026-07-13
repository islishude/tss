// Package secp256k1 exposes the CGGMP21/secp256k1 threshold ECDSA API.
//
// Keygen uses Shamir shares, public commitments, Paillier key material, and
// proof bindings. Explicit APIs support trusted-dealer import and authorized
// threshold reconstruction; ordinary signing never reconstructs private key or
// nonce shares and uses Paillier MtA/MtAwc-style product sharing. The ZK proof
// layer has been prepared for independent cryptographic review; see
// docs/audit-guide.md.
//
// # Handler template
//
// Every inbound protocol message handler follows the same transactional pattern:
//
//	decode → policy validate → cryptographic verify → prepare transition → commit → effects
//
//	 1. DECODE: decode the wire payload, fail-closed on malformed input
//	 2. POLICY VALIDATE: transport-layer checks are performed before this step
//	    by the shared [tss.ValidateInbound]; handlers also check round and duplicate state
//	 3. CRYPTOGRAPHIC VERIFY: proof verification, ciphertext membership, curve checks
//	 4. PREPARE TRANSITION: own decoded secret material without mutating session state
//	 5. COMMIT: atomically install verified state and transfer prepared ownership
//	 6. EFFECTS: emit already-constructed envelopes or invoke durable coordination
//
// Rejected transitions destroy uncommitted secret material. Readiness is
// derived from accepted per-party state rather than manually maintained counts.
// Persisted presigns contain only the normalized Figure 8 tuple and public
// commitments needed to verify Figure 10 partial signatures. Sign recovery is
// driven by the durable lifecycle attempt and exact outbox, never by reusing
// the one-use signing tuple.
package secp256k1
