# Shared Test Harness

`internal/testharness` contains small, protocol-neutral helpers for deterministic
tests, envelope fault injection, public-state snapshots, lifecycle runners, and
crash/restart simulation. Protocol-specific setup and cryptographic mutations
stay with the protocol that owns them; general assertions and fixture helpers
live in `internal/testutil`.

The Go source is the API contract. This file explains intended use and the
security constraints that are easy to miss.

## Deterministic Inputs

- `Reader(t)` returns a deterministic byte stream using seed `42`, or the value
  of `TSS_TEST_SEED` when set. The active seed is logged for reproduction.
- `Parties(n)` returns the sorted set `{1, ..., n}`.
- `ThresholdCase` supplies `N()` and `T()` for table-driven threshold cases.
- `SignerSubset(all, ids...)` selects 1-based positions from an existing party
  set. Test setup must provide valid indices.

These readers are test fixtures, not cryptographic randomness. Tests that use a
different random source must still make failures reproducible.

## Envelope Faults

`DeliverMessages` applies a `NetworkConfig` to one batch of envelopes:

- `Drop` removes matching envelopes;
- `Duplicate` emits a second copy;
- `Mutate` transforms every delivered copy; and
- `Reorder` shuffles the final batch when a non-nil `*rand.Rand` is supplied.

The mutation helpers cover wrong session, protocol, round, sender, or recipient;
payload corruption; sender/recipient swapping; and conflicting payloads for one
sender/round slot. They return modified envelope values and do not update
authentication metadata outside the envelope. Tests must therefore pass the
result through the same authenticated opening and policy path used in
production.

Protocol-specific faults, such as changing a proof field while preserving a
canonical payload, belong in that protocol's tests.

## Protocol Runner

`ProtocolCase` models a table-driven lifecycle through `Start`, repeated `Step`
calls, `Done`, and `AssertSuccess`. `Run` stops at the first step error. The
runner does not choose delivery order, retry rejected input, or infer a
fail-closed assertion; the case owns those decisions.

`Session` carries a party ID and an outbox accessor. `ProtocolResult` is an
available result shape for callers that need to record an error, resulting
outbox, and whether a delivery advanced state; `Run` does not construct it.

## Public-State Snapshots

`CaptureSnapshot` records only `CurrentRound`, `OutboxCount`, `IsConsumed`, and
`IsComplete` from a `Snapshotter`. Implementations must not expose secret state
through those methods.

`AssertNoSideEffect` checks that a rejection did not change the round or outbox
and did not newly mark one-use state consumed. Completion is captured so a test
can assert the phase-specific contract explicitly; the helper does not compare
it automatically.

## Crash/Restart Store

`CrashyStore` is a clone-on-read, single-blob, in-memory compare-and-swap store
for tests. It can inject one crash at any of these points:

- `CrashBeforePersist` leaves the old blob installed;
- `CrashAfterPersist` installs the replacement and returns an unknown-outcome
  error; and
- `CrashBeforeOutbound` / `CrashAfterOutbound` are triggered explicitly with
  `Hit` around message emission.

`CompareAndSwap` takes ownership of the proposed replacement and clears the
caller-provided slice on success, conflict, and injected persistence failure.
`Load` returns an independent copy. Call `Destroy` to clear the retained blob
after the test.

This store models lifecycle boundaries; it is not a production durability or
secure-erasure implementation.
