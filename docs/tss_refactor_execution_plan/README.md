# TSS Protocol State Machine Refactor Execution Plan

This directory contains the staged execution plan for refactoring the protocol session internals in:

- `frost/ed25519`
- `cggmp21/secp256k1`

The plan is intentionally split into small, reviewable phases. Each phase file is intended to map to one pull request or a small group of tightly related pull requests.

## Primary goals

1. Enforce the protocol handler structure:

   ```text
   decode -> policy validate -> cryptographic verify -> prepare transition -> commit -> effects
   ```

2. Make reject paths non-mutating by construction.
3. Make secret ownership transfer explicit and auditable.
4. Make outbound emission atomic with respect to state mutation.
5. Replace fragile counters with derived readiness predicates where practical.
6. Decouple online cryptographic state machines from durable storage coordination.
7. Extend the same design discipline across both `frost/ed25519` and `cggmp21/secp256k1`.

## File map

| File                                | Purpose                                                                                            |
| ----------------------------------- | -------------------------------------------------------------------------------------------------- |
| `STATUS.md`                         | Single source of truth for phase completion and open questions.                                    |
| `00-baseline-and-invariants.md`     | Add snapshot helpers and no-mutation tests before production refactors.                            |
| `01-local-helpers.md`               | Add protocol-local helpers such as `slot`, `partyTable`, cleanup stack, and transition interfaces. |
| `02-frost-sign.md`                  | Refactor FROST signing into immutable context, state, resources, transitions, and atomic effects.  |
| `03-frost-keygen.md`                | Refactor FROST keygen, pending share creation, confirmation handling, and finalization.            |
| `04-frost-reshare-refresh.md`       | Refactor FROST reshare and refresh with explicit mode/role and atomic completion.                  |
| `05-cggmp-keygen.md`                | Apply the transition model to CGGMP keygen and key share finalization.                             |
| `06-cggmp-presign.md`               | Apply the transition model to CGGMP presign round1/round2/round3.                                  |
| `07-cggmp-online-sign-and-store.md` | Decouple CGGMP online signing from durable sign-attempt coordination.                              |
| `08-readiness-and-cleanup.md`       | Remove counters, consolidate cleanup, update documentation, and run final test matrix.             |

## Execution policy

- Keep each phase independently reviewable.
- Avoid public API changes unless a safety issue requires one.
- Do not introduce wire compatibility shims.
- Do not change protocol math as part of structural refactoring.
- Avoid generic cross-package frameworks until the local pattern has proven itself in both packages.
- Production handler code must not mutate session state before policy and cryptographic verification are complete.
- Prepared secret-bearing values must be destroyed unless ownership is explicitly committed.
