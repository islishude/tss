// Package secp256k1 exposes the CGGMP21/secp256k1 threshold ECDSA API.
//
// Keygen uses Shamir shares, public commitments, Paillier key material, and
// proof bindings. Signing avoids reconstructing private key or nonce shares and
// uses Paillier MtA/MtAwc-style product sharing. The ZK proof layer has been
// prepared for independent cryptographic review; see docs/audit-guide.md.
//
// # Handler template
//
// Every inbound protocol message handler follows the same five-step pattern:
//
//		parse → policy validate → cryptographic verify → mutate state → emit
//
//	 1. PARSE: decode the wire payload, fail-closed on malformed input
//	 2. POLICY VALIDATE: transport-layer checks are performed before this step
//	    by the shared [tss.ValidateInbound]; handlers only check round / duplicate
//	 3. CRYPTOGRAPHIC VERIFY: proof verification, ciphertext membership, curve checks
//	 4. MUTATE STATE: record the verified data, update round-specific maps
//	 5. EMIT: advance the protocol by calling tryEmitRound* or tryComplete*
//
// Steps 2 (duplicate/replay) and basic round checks are performed by the
// Handle*Message dispatcher before delegating to the per-round handler.
package secp256k1
