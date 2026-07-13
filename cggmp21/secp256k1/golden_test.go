//go:build integration

package secp256k1

import (
	"bytes"
	"encoding/hex"
	"math/rand"
	"os"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testvectors"
)

func TestGoldenCGGMP21KeyShare(t *testing.T) {
	const golden = "wire/v1/cggmp21/KeyShare.golden"
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		rng := rand.New(rand.NewSource(700)) //nolint:gosec // deterministic vector input
		session, err := tss.NewSessionID(rng)
		if err != nil {
			t.Fatal(err)
		}
		parties := tss.NewPartySet(1, 2, 3)
		sessions := make(map[tss.PartyID]*KeygenSession, len(parties))
		messages := make([]tss.Envelope, 0)
		for _, id := range parties {
			cfg := tss.ThresholdConfig{
				Threshold: 2, Parties: parties, Self: id, SessionID: session,
				Rand: rand.New(rand.NewSource(int64(id * 100))), //nolint:gosec // deterministic vector input
			}
			kg, out, err := startCGGMP21Keygen(cfg)
			if err != nil {
				t.Fatal(err)
			}
			sessions[id] = kg
			messages = append(messages, out...)
		}
		deliverKeygenMessages(t, sessions, parties, messages)
		share, ok := sessions[1].KeyShare()
		if !ok {
			t.Fatal("keygen not complete")
		}
		defer share.Destroy()
		raw, err := share.MarshalBinaryWithLimits(testLimits())
		if err != nil {
			t.Fatal(err)
		}
		writeCGGMPGolden(t, golden, raw)
		return
	}
	assertCGGMPGoldenRoundTrip(t, golden, func(raw []byte) ([]byte, error) {
		decoded, err := tss.DecodeBinaryWithLimits[KeyShare](raw, testLimits())
		if err != nil {
			return nil, err
		}
		defer decoded.Destroy()
		return decoded.MarshalBinaryWithLimits(testLimits())
	})
}

func TestGoldenCGGMP21Presign(t *testing.T) {
	const golden = "wire/v1/cggmp21/Presign.golden"
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		shares := CachedKeygenShares(t, 1, 1)
		presigns := secpPresign(t, shares, tss.NewPartySet(1))
		raw, err := presigns[1].MarshalBinaryWithLimits(testLimits())
		if err != nil {
			t.Fatal(err)
		}
		writeCGGMPGolden(t, golden, raw)
		return
	}
	assertCGGMPGoldenRoundTrip(t, golden, func(raw []byte) ([]byte, error) {
		decoded, err := tss.DecodeBinaryWithLimits[Presign](raw, testLimits())
		if err != nil {
			return nil, err
		}
		defer decoded.Destroy()
		return decoded.MarshalBinaryWithLimits(testLimits())
	})
}

func writeCGGMPGolden(t *testing.T, name string, raw []byte) {
	t.Helper()
	path, err := testvectors.Path(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(raw)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertCGGMPGoldenRoundTrip(t *testing.T, name string, roundTrip func([]byte) ([]byte, error)) {
	t.Helper()
	wantHex := testvectors.Read(t, name)
	raw, err := hex.DecodeString(string(bytes.TrimSpace(wantHex)))
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := roundTrip(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, raw2) {
		t.Error("round-trip produced different encoding")
	}
	if _, err := roundTrip(append(raw, 0)); err == nil {
		t.Error("accepted trailing byte")
	}
}
