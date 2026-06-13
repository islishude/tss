package ed25519

import (
	"errors"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

// --- FROST keygen fail-closed matrix ---

func TestFROSTKeygenEnvelopeFailClosed(t *testing.T) {
	t.Parallel()

	parties := []tss.PartyID{1, 2}
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}

	kg1, _, err := startFROSTKeygen(tss.ThresholdConfig{
		Threshold: 2,
		Parties:   parties,
		Self:      1,
		SessionID: sessionID,
	}, testFROSTGuard(1, tss.PartySet(parties), sessionID))
	if err != nil {
		t.Fatal(err)
	}

	_, out2, err := startFROSTKeygen(tss.ThresholdConfig{
		Threshold: 2,
		Parties:   parties,
		Self:      2,
		SessionID: sessionID,
	}, testFROSTGuard(2, tss.PartySet(parties), sessionID))
	if err != nil {
		t.Fatal(err)
	}

	// Base envelopes: out2[0] = broadcast commitment, out2[1] = direct share to party 1.
	commit := out2[0]
	if commit.PayloadType != payloadKeygenCommitments {
		t.Fatalf("expected payloadKeygenCommitments, got %q", commit.PayloadType)
	}
	commit.Security.Authenticated = true
	commit.Security.AuthenticatedParty = commit.From

	share := out2[1]
	if share.PayloadType != payloadKeygenShare {
		t.Fatalf("expected payloadKeygenShare, got %q", share.PayloadType)
	}
	share.Security.Authenticated = true
	share.Security.AuthenticatedParty = share.From

	tests := []struct {
		name     string
		base     tss.Envelope
		mutate   func(tss.Envelope) tss.Envelope
		wantErr  error  // sentinel error (checked with errors.Is)
		wantCode string // protocol error code (checked with assertFROSTProtocolCode)
	}{
		{
			name: "wrong session", base: commit,
			mutate: func(env tss.Envelope) tss.Envelope {
				wrongID, _ := tss.NewSessionID(nil)
				env.SessionID = wrongID
				return env
			},
			wantCode: tss.ErrCodeInvalidMessage,
		},
		{
			name: "wrong protocol", base: commit,
			mutate: func(env tss.Envelope) tss.Envelope {
				env.Protocol = "wrong-protocol"
				return env
			},
			wantCode: tss.ErrCodeInvalidMessage,
		},
		{
			name: "wrong round", base: commit,
			mutate: func(env tss.Envelope) tss.Envelope {
				env.Round = 2
				return env
			},
			wantCode: tss.ErrCodeInvalidMessage,
		},
		{
			name: "wrong recipient on share", base: share,
			mutate: func(env tss.Envelope) tss.Envelope {
				env.To = 99
				return env
			},
			wantErr: tss.ErrWrongRecipient,
		},
		{
			name: "broadcast secret share", base: share,
			mutate: func(env tss.Envelope) tss.Envelope {
				env.To = 0
				return env
			},
			wantErr: tss.ErrExpectedDirectMessage,
		},
		{
			name: "non-confidential share", base: share,
			mutate: func(env tss.Envelope) tss.Envelope {
				env.Security.Confidential = false
				return env
			},
			wantErr: tss.ErrMissingConfidentiality,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mutated := tc.mutate(tc.base)
			mutated = mutated.RecomputeTranscriptHash()
			mutated.Security.Authenticated = true
			mutated.Security.AuthenticatedParty = mutated.From

			_, err := kg1.HandleKeygenMessage(testutil.DeliverEnvelope(mutated))
			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if tc.wantCode != "" {
				_ = assertFROSTProtocolCode(t, err, tc.wantCode)
			} else {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("expected error %v, got %v", tc.wantErr, err)
				}
			}
		})
	}

	// Duplicate commitment: use a fresh session so the first delivery does not interfere.
	t.Run("duplicate commitment", func(t *testing.T) {
		t.Parallel()

		sess2, _, err := startFROSTKeygen(tss.ThresholdConfig{
			Threshold: 2,
			Parties:   parties,
			Self:      1,
			SessionID: sessionID,
		}, testFROSTGuard(1, tss.PartySet(parties), sessionID))
		if err != nil {
			t.Fatal(err)
		}

		dup := commit
		dup.Security.Authenticated = true
		dup.Security.AuthenticatedParty = dup.From
		dup = dup.RecomputeTranscriptHash()
		dup.Security.Authenticated = true
		dup.Security.AuthenticatedParty = dup.From

		_, _ = sess2.HandleKeygenMessage(testutil.DeliverEnvelope(dup))
		_, err = sess2.HandleKeygenMessage(testutil.DeliverEnvelope(dup))
		if !errors.Is(err, tss.ErrDuplicateMessage) {
			t.Fatalf("expected ErrDuplicateMessage on second delivery, got %v", err)
		}
	})
}

// --- FROST sign fail-closed matrix ---

func TestFROSTSignEnvelopeFailClosed(t *testing.T) {
	t.Parallel()

	shares := frostKeygen(t, 2, 3)
	parties := tss.SortParties(shares[1].state.parties)
	signers := []tss.PartyID{1, 2}
	message := []byte("test-message")

	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}

	sign1, _, err := startFROSTSign(shares[1], sessionID, signers, message, testFROSTGuard(1, tss.PartySet(parties), sessionID))
	if err != nil {
		t.Fatal(err)
	}

	_, out2, err := startFROSTSign(shares[2], sessionID, signers, message, testFROSTGuard(2, tss.PartySet(parties), sessionID))
	if err != nil {
		t.Fatal(err)
	}
	commit2 := out2[0]
	if commit2.PayloadType != payloadSignCommitment {
		t.Fatalf("expected payloadSignCommitment, got %q", commit2.PayloadType)
	}
	commit2.Security.Authenticated = true
	commit2.Security.AuthenticatedParty = commit2.From

	// Start party 3 (not a signer) to get a commitment from outside the signer set.
	// Use a separate signer set that includes party 3.
	signersWith3 := []tss.PartyID{1, 2, 3}
	_, out3, err := startFROSTSign(shares[3], sessionID, signersWith3, message, testFROSTGuard(3, tss.PartySet(parties), sessionID))
	if err != nil {
		t.Fatal(err)
	}
	commit3 := out3[0]
	commit3.Security.Authenticated = true
	commit3.Security.AuthenticatedParty = commit3.From

	// Get a partial signature by completing a sign flow.
	_, partials := frostSigningRound2(t, 2, 3, signers, message)
	if len(partials) == 0 {
		t.Fatal("expected partial signatures")
	}
	partial := partials[0]
	partial.Security.Authenticated = true
	partial.Security.AuthenticatedParty = partial.From

	tests := []struct {
		name     string
		env      tss.Envelope
		mutate   func(tss.Envelope) tss.Envelope
		wantErr  error  // sentinel error
		wantCode string // protocol error code
	}{
		{
			name: "wrong session", env: commit2,
			mutate: func(env tss.Envelope) tss.Envelope {
				wrongID, _ := tss.NewSessionID(nil)
				env.SessionID = wrongID
				return env
			},
			wantCode: tss.ErrCodeInvalidMessage,
		},
		{
			name: "wrong protocol", env: commit2,
			mutate: func(env tss.Envelope) tss.Envelope {
				env.Protocol = "wrong-protocol"
				return env
			},
			wantCode: tss.ErrCodeInvalidMessage,
		},
		{
			name: "wrong round on commitment", env: commit2,
			mutate: func(env tss.Envelope) tss.Envelope {
				env.Round = 2
				return env
			},
			wantCode: tss.ErrCodeInvalidMessage, // guard rejects before handler round check
		},
		{
			name: "wrong round on partial", env: partial,
			mutate: func(env tss.Envelope) tss.Envelope {
				env.Round = 1
				return env
			},
			wantCode: tss.ErrCodeInvalidMessage, // guard rejects before handler round check
		},
		{
			name: "sender not signer", env: commit3,
			mutate: func(env tss.Envelope) tss.Envelope {
				return env // already has From=3, which is not in signers {1,2}
			},
			wantCode: tss.ErrCodeInvalidMessage,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mutated := tc.mutate(tc.env)
			mutated = mutated.RecomputeTranscriptHash()
			mutated.Security.Authenticated = true
			mutated.Security.AuthenticatedParty = mutated.From

			_, err := sign1.HandleSignMessage(testutil.DeliverEnvelope(mutated))
			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if tc.wantCode != "" {
				_ = assertFROSTProtocolCode(t, err, tc.wantCode)
			} else {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("expected error %v, got %v", tc.wantErr, err)
				}
			}
		})
	}

	// Duplicate commitment: fresh session.
	t.Run("duplicate commitment", func(t *testing.T) {
		t.Parallel()

		sess2, _, err := startFROSTSign(shares[1], sessionID, signers, message, testFROSTGuard(1, tss.PartySet(parties), sessionID))
		if err != nil {
			t.Fatal(err)
		}

		dup := commit2
		dup.Security.Authenticated = true
		dup.Security.AuthenticatedParty = dup.From
		dup = dup.RecomputeTranscriptHash()
		dup.Security.Authenticated = true
		dup.Security.AuthenticatedParty = dup.From

		_, _ = sess2.HandleSignMessage(testutil.DeliverEnvelope(dup))
		_, err = sess2.HandleSignMessage(testutil.DeliverEnvelope(dup))
		if !errors.Is(err, tss.ErrDuplicateMessage) {
			t.Fatalf("expected ErrDuplicateMessage on second delivery, got %v", err)
		}
	})

	// Completed session rejects partial: after aggregation, duplicate delivery returns completion.
	t.Run("completed session rejects partial", func(t *testing.T) {
		t.Parallel()

		dupSessionID, _ := tss.NewSessionID(nil)
		signers2 := []tss.PartyID{1, 2}

		// Start party 1 with 2 signers so delivery of party 2's partial triggers completion.
		sess1, out1, err := startFROSTSign(shares[1], dupSessionID, signers2, message, testFROSTGuard(1, tss.PartySet(parties), dupSessionID))
		if err != nil {
			t.Fatal(err)
		}

		// Start party 2.
		sess2, out2, err := startFROSTSign(shares[2], dupSessionID, signers2, message, testFROSTGuard(2, tss.PartySet(parties), dupSessionID))
		if err != nil {
			t.Fatal(err)
		}

		// Deliver party 2's commitment to party 1 → party 1 emits its partial.
		cb := out2[0]
		cb.Security.Authenticated = true
		cb.Security.AuthenticatedParty = cb.From
		_, err = sess1.HandleSignMessage(testutil.DeliverEnvelope(cb))
		if err != nil {
			t.Fatal(err)
		}

		// Deliver party 1's commitment to party 2 → party 2 emits its partial.
		ca := out1[0]
		ca.Security.Authenticated = true
		ca.Security.AuthenticatedParty = ca.From
		party2Partials, err := sess2.HandleSignMessage(testutil.DeliverEnvelope(ca))
		if err != nil {
			t.Fatal(err)
		}
		if len(party2Partials) == 0 || party2Partials[0].PayloadType != payloadSignPartial {
			t.Fatal("expected party 2 to emit partial after receiving commitment")
		}
		party2Partial := party2Partials[0]
		party2Partial.Security.Authenticated = true
		party2Partial.Security.AuthenticatedParty = party2Partial.From

		// First delivery of party 2's partial to party 1 triggers aggregation → session completes.
		_, err = sess1.HandleSignMessage(testutil.DeliverEnvelope(party2Partial))
		if err != nil {
			t.Fatal(err)
		}

		// Second delivery of any valid message to a completed session is rejected.
		_, err = sess1.HandleSignMessage(testutil.DeliverEnvelope(party2Partial))
		_ = assertFROSTProtocolCode(t, err, tss.ErrCodeCompleted)
	})
}

// --- FROST reshare fail-closed matrix ---

func TestFROSTReshareEnvelopeFailClosed(t *testing.T) {
	t.Parallel()

	shares := frostKeygen(t, 2, 2)
	oldParties := []tss.PartyID{1, 2}
	newParties := oldParties // same committee

	reshareSessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}

	reshare1, _, err := startFROSTReshare(shares[1], newParties, 2, tss.ThresholdConfig{
		Threshold: 2,
		Parties:   newParties,
		Self:      1,
		SessionID: reshareSessionID,
	}, testFROSTGuard(1, tss.PartySet(oldParties), reshareSessionID))
	if err != nil {
		t.Fatal(err)
	}

	_, out2, err := startFROSTReshare(shares[2], newParties, 2, tss.ThresholdConfig{
		Threshold: 2,
		Parties:   newParties,
		Self:      2,
		SessionID: reshareSessionID,
	}, testFROSTGuard(2, tss.PartySet(oldParties), reshareSessionID))
	if err != nil {
		t.Fatal(err)
	}

	// out2[0] = broadcast reshare commitments, out2[1] = direct share to party 1.
	commit := out2[0]
	commit.Security.Authenticated = true
	commit.Security.AuthenticatedParty = commit.From

	share := out2[1]
	share.Security.Authenticated = true
	share.Security.AuthenticatedParty = share.From

	tests := []struct {
		name     string
		base     tss.Envelope
		mutate   func(tss.Envelope) tss.Envelope
		wantErr  error  // sentinel error
		wantCode string // protocol error code
	}{
		{
			name: "wrong session", base: commit,
			mutate: func(env tss.Envelope) tss.Envelope {
				wrongID, _ := tss.NewSessionID(nil)
				env.SessionID = wrongID
				return env
			},
			wantCode: tss.ErrCodeInvalidMessage,
		},
		{
			name: "wrong protocol", base: commit,
			mutate: func(env tss.Envelope) tss.Envelope {
				env.Protocol = "wrong-protocol"
				return env
			},
			wantCode: tss.ErrCodeInvalidMessage,
		},
		{
			name: "wrong round", base: commit,
			mutate: func(env tss.Envelope) tss.Envelope {
				env.Round = 99
				return env
			},
			wantCode: tss.ErrCodeInvalidMessage,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mutated := tc.mutate(tc.base)
			mutated = mutated.RecomputeTranscriptHash()
			mutated.Security.Authenticated = true
			mutated.Security.AuthenticatedParty = mutated.From

			_, err := reshare1.HandleReshareMessage(testutil.DeliverEnvelope(mutated))
			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if tc.wantCode != "" {
				_ = assertFROSTProtocolCode(t, err, tc.wantCode)
			} else {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("expected error %v, got %v", tc.wantErr, err)
				}
			}
		})
	}

	// Missing confidentiality on direct share.
	t.Run("missing confidentiality on share", func(t *testing.T) {
		t.Parallel()

		mutated := share
		mutated.Security.Confidential = false
		mutated = mutated.RecomputeTranscriptHash()
		mutated.Security.Authenticated = true
		mutated.Security.AuthenticatedParty = mutated.From

		_, err := reshare1.HandleReshareMessage(testutil.DeliverEnvelope(mutated))
		if !errors.Is(err, tss.ErrMissingConfidentiality) {
			t.Fatalf("expected ErrMissingConfidentiality, got %v", err)
		}
	})
}
