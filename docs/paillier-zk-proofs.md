# Paillier and Zero-Knowledge Proof Notes

This document inventories the proof systems used by
`cggmp21/secp256k1`. Relations and figure numbers refer to the bundled 2024
revision of [`cggmp21.pdf`](cggmp21.pdf). The repository implementation has not
received an independent cryptographic review.

## Production Profile

`DefaultSecurityParams()` returns:

```text
Ell             = 256
EllPrime        = 1280
Epsilon         = 512
ChallengeBits   = 256
MinPaillierBits = 3072
```

This follows Appendix C.1 for secp256k1:
`(Ell,Epsilon,EllPrime)=(kappa,2*kappa,5*kappa)` with `kappa=256`.
The paper identifies 3072-bit Paillier and Pedersen moduli with 128-round
`Πmod`/`Πprm` amplification as the 128-bit profile. The curve itself also has an
approximately 128-bit classical security level.

Each participant generates two independent moduli:

- Paillier `N=pq`, used for encryption and MtA; and
- auxiliary `Nhat`, used with Ring-Pedersen bases `(s,t)`.

Both must meet `MinPaillierBits`, but they must not be equal and must not share
one factorization. Verifiers reject reuse of a statement Paillier modulus as
the auxiliary modulus.

Reduced profiles are explicit test inputs. Security parameters are bound into
plans, persisted records, and every applicable proof transcript.

## Proof Inventory

### Active paper-path proofs

| Proof      | Paper relation and active use                                                       | Main verifier checks                                                                                                 | Canonical wire type               |
| ---------- | ----------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- | --------------------------------- |
| Schnorr    | Figure 6 key contribution and Figure 7/F.1 polynomial coefficients                  | Canonical points/scalars, committed first message, common RID/coin domain, party and coefficient                     | `internal/zk/schnorr.Proof`       |
| `Πprm`     | Figure 7 auxiliary `(Nhat,s,t)`, using the repository CGGMP24-style parameter proof | Independent auxiliary modulus, unit/Jacobi checks, exactly 128 verifier-derived bits, response bounds, `t^z = A*s^e` | `zk.paillier.ring-pedersen-proof` |
| `Πmod`     | Figure 7 Paillier-Blum modulus                                                      | Odd composite modulus, exactly 128 verifier-derived rounds, unit/Jacobi checks, all root equations                   | `zk.paillier.modulus-proof`       |
| `Πfac`     | Figure 7 receiver-specific bounded-factor statement                                 | Prover `N`, recipient `(Nhat,s,t)`, factor ranges, unit/range checks, three Ring-Pedersen equations                  | `zk.paillier.factor-proof`        |
| `Πenc-elg` | Figure 8 round 1 for both encrypted `k_i` and `gamma_i`                             | Ciphertext membership, plaintext range, ElGamal commitment equations, recipient auxiliary setup, shared challenge    | `zk.paillier.enc-elg-proof`       |
| `Πelog`    | Figure 8 round 2 for `Gamma_i` and round 3 for `Delta_i`                            | Canonical non-identity points, shared scalar responses, both ElGamal/discrete-log equations                          | `zk.paillier.elog-proof`          |
| `Πaff-g`   | Figure 8 round 2 pairwise affine responses                                          | Both Paillier moduli, recipient auxiliary setup, ciphertext membership, signed ranges, Paillier and curve equations  | `zk.paillier.aff-g-proof`         |
| `Πaff-g*`  | Figure 9 setup-less peer relation                                                   | Exact public MtA response pair, both moduli, bit-amplified equations, bounded responses                              | `zk.paillier.aff-g-star-proof`    |
| `Πdec`     | Figure 9 aggregate decryption relation                                              | Aggregate ciphertext, public curve relation, bit-amplified equations, bounded responses                              | `zk.paillier.dec-proof`           |

Figure 10 needs no additional zero-knowledge proof. It verifies each partial
directly using the normalized Figure 8 commitments.

### Retained primitives

The following canonical primitives remain in `internal/zk/paillier` but do not
replace the active Figure 6-10 relations above:

| Primitive                | Current role                                                                                                                                          |
| ------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Πenc` (`EncProof`)      | Standalone range-proof primitive and tests; not emitted by the active Figure 8 path.                                                                  |
| `Πlog*` (`LogStarProof`) | Used by the temporary reshare handoff and retained MtA helpers; it is not the Figure 8 round-1 relation and is not part of the final refreshed epoch. |
| `Πmul`, `Πmul*`          | Retained internal primitives and tests; the active Figure 9 payload uses `Πaff-g*` and `Πdec`.                                                        |

Unsupported historical proof shapes have no compatibility decoder. Protocol
state must be regenerated through the current flows.

## Figure 7 Proof Schedule

Figure 7 commits before its final proof domains are known:

1. Each party prepares independent Paillier and auxiliary factorization state,
   the `Πmod` first-message commitment, `Πprm`, polynomial commitments, Schnorr
   first messages, DH keys, RID contribution, and decommitment.
2. The party broadcasts only a hash commitment.
3. After all openings verify, every party derives the common RID, dynamic
   identifiers, and target epoch.
4. Schnorr proofs and `Πmod` are finalized under that common context.
5. Each recipient receives a distinct `Πfac` whose statement uses that
   recipient's `(Nhat,s,t)`.

Proof objects are prepared before the state transition that makes their
envelopes visible. A marshal, envelope, replay, or commit failure destroys
uncommitted proof state and retained factors.

## Figure 8 Proof Schedule

Round 1 uses `Πenc-elg`, not a ciphertext-to-fixed-base discrete-log proof. For
the encrypted nonce `K_i`, the statement binds:

```text
K_i = Enc_i(k_i)
A_i,1 = [a_i]G
A_i,2 = [a_i]Y_i + [k_i]G
```

The encrypted `gamma_i` statement uses the corresponding `B_i` pair. Each
proof is recipient-specific because it uses that recipient's independent
auxiliary parameters.

Round 2 uses `Πelog` to bind `Gamma_i=[gamma_i]G` to the round-1 `B_i` pair.
Each delta and chi MtA response carries `Πaff-g`, binding the responder scalar,
wide signed affine mask, response ciphertexts, curve commitment, both Paillier
keys, and recipient auxiliary setup.

Round 3 uses `Πelog` to bind `Delta_i=[k_i]Gamma` to the round-1 `A_i` pair.
The aggregate equations are then checked directly; no repository-specific
replacement proof is inserted.

## Figure 9 Proof Schedule

On an aggregate delta or chi failure, each signer creates one public record for
the selected relation:

- the canonical inbound and outbound MtA response for every peer;
- one setup-less `Πaff-g*` per peer; and
- one `Πdec` over the aggregated ciphertext and claimed curve result.

These proofs use independent bit challenges. The canonical payload is bounded
before decode and before replay state is committed. Evidence contains only
public proof material and authenticated envelopes; witnesses, factors, masks,
nonce shares, and Paillier randomness are forbidden.

## Challenge Derivation

Repository-defined transcript entries use typed, labeled encodings. Every
proof domain binds its proof tag and version, the security profile, protocol
context, prover, recipient when applicable, and the complete public statement
and commitment set.

Field-scalar Fiat-Shamir challenges are produced by labeled SHA-256 expansion
and rejection sampling. The accepted representative is canonical and non-zero:

```text
1 <= e < q
```

Modulus challenges sample uniformly below the modulus with the standard
multiple-of-`N` cutoff and then reject non-units. The field and modulus samplers
are bounded and fail closed after 256 attempts. `Πmod` and `Πprm` retain their
fixed 128-round amplification required by the profile.

Proof decoders never accept a prover-supplied challenge in place of transcript
derivation.

## Integer and Ciphertext Boundaries

- Paillier ciphertexts are checked for membership in `Z*_(N^2)` before
  algebraic verification.
- Ring-Pedersen parameters and commitments are checked in `Z*_(Nhat)` with the
  required public Jacobi conditions.
- Signed responses use canonical signed-magnitude TLV encoding. Verifier range
  checks precede proof equations.
- MtA affine masks are fixed-width signed integers in the `EllPrime` range, not
  curve scalars.
- Paillier decryption converts a plaintext to the centered representative
  before reduction modulo the secp256k1 order. Treating a negative mask as its
  unsigned residue modulo `N` changes the protocol relation.
- The configured modulus size must cover the largest paper plaintext range and
  aggregation slack; validation fails before proof work when it cannot.

## Constant-Time Boundary

Secret-exponent modular exponentiation goes through
`internal/paillier/paillierct` using fixed-width encodings and
`filippo.io/bigmod`:

| Secret operation                      | Required path                 |
| ------------------------------------- | ----------------------------- |
| Paillier private decryption exponent  | `paillierct.ExpSecretBlinded` |
| MtA responder scalar exponentiation   | `paillierct.ExpCT`            |
| Secret signed Ring-Pedersen exponents | constant-time signed helpers  |

This is a limited boundary, not a claim that the complete implementation,
proof generation, Go runtime, or key generation is constant time. Public
verification arithmetic may use variable-time `math/big` operations.

## Canonical Decoder Boundary

Every proof uses `internal/wire` version-1 typed TLV. Decoders reject:

- wrong proof type or schema version;
- missing, extra, duplicate, or unsorted fields;
- trailing bytes;
- non-canonical or oversized integers;
- invalid curve points, ciphertexts, or group elements;
- response-count mismatches; and
- nested records exceeding the enclosing protocol limits.

There is no JSON fallback or proof-conversion path in production code.

## Verification Evidence

Tests cover, at the appropriate tier:

- canonical encode/decode and exact field sets;
- statement, domain, party, recipient, epoch, and security-profile mutation;
- exact range boundaries and non-members;
- proof omission and bit-flip rejection at the protocol layer;
- special-soundness extraction for retained single-challenge range proofs;
- fixed-round challenge derivation and zero-challenge guards;
- independent `N`/`Nhat` generation and equality rejection;
- Figure 8 equations and Figure 9 all-valid/invariant behavior; and
- production-parameter smoke tests behind `slowcrypto`.

These tests are evidence about the implementation. They are not a formal proof
or independent cryptographic audit.

## Known Limitations and Review Requirements

1. The Paillier/ZK code, Fiat-Shamir composition, and concrete range analysis
   need independent review against the bundled paper.
2. The repository uses CGGMP24-style `Πmod` and `Πprm` constructions within the
   2024 CGGMP21 protocol schedule; that composition needs explicit review.
3. The Appendix F.1 threshold adaptation, repository epoch bindings, and
   lifecycle transaction model extend beyond the paper's exact implementation
   description.
4. Secret cleanup is best effort in Go and is not a memory-forensic guarantee.
5. Production use also requires independently reviewed randomness, transport,
   storage encryption, database transactions, key management, and operational
   recovery.
