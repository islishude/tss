package ed25519

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
)

func TestFROSTKeyShareCanonicalEncoding(t *testing.T) {
	shares := frostKeygen(t, 2, 3)
	raw1, err := shares[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := shares[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw1, raw2) {
		t.Fatal("key share encoding is not deterministic")
	}
	decoded, err := UnmarshalKeyShare(raw1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.PublicKey, shares[1].PublicKey) {
		t.Fatal("public key mismatch after canonical round trip")
	}
	if _, err := UnmarshalKeyShare([]byte(`{"version":1}`)); err == nil {
		t.Fatal("JSON key share encoding accepted")
	}
	trailing := append(append([]byte(nil), raw1...), 0)
	if _, err := UnmarshalKeyShare(trailing); err == nil {
		t.Fatal("key share with trailing bytes accepted")
	}
}

func TestFROSTKeyShareRejectsNonCanonicalFields(t *testing.T) {
	shares := frostKeygen(t, 2, 3)
	unsorted := cloneFROSTKeyShare(shares[1])
	unsorted.Parties[0], unsorted.Parties[1] = unsorted.Parties[1], unsorted.Parties[0]
	if _, err := unsorted.MarshalBinary(); err == nil {
		t.Fatal("unsorted party set encoded")
	}
	malformed := cloneFROSTKeyShare(shares[1])
	malformed.PublicKey = []byte{0x01}
	if _, err := malformed.MarshalBinary(); err == nil {
		t.Fatal("malformed public key encoded")
	}
}

func FuzzFROSTKeyShareUnmarshal(f *testing.F) {
	shares := frostKeygenForFuzz(f, 1, 1)
	raw, err := shares[1].MarshalBinary()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"version":1}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		share, err := UnmarshalKeyShare(data)
		if err != nil {
			return
		}
		assertPayloadRemarshals(t, share, (*KeyShare).MarshalBinary, UnmarshalKeyShare)
	})
}

func FuzzFROSTKeygenCommitmentsPayloadUnmarshal(f *testing.F) {
	raw, err := marshalKeygenCommitmentsPayload(keygenCommitmentsPayload{
		Commitments: [][]byte{seedFROSTPoint(f)},
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"commitments":[]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := unmarshalKeygenCommitmentsPayload(data)
		if err != nil {
			return
		}
		assertPayloadRemarshals(t, p, marshalKeygenCommitmentsPayload, unmarshalKeygenCommitmentsPayload)
	})
}

func FuzzFROSTKeygenSharePayloadUnmarshal(f *testing.F) {
	raw, err := marshalKeygenSharePayload(keygenSharePayload{Share: seedFROSTScalar(f)})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"share":"x"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := unmarshalKeygenSharePayload(data)
		if err != nil {
			return
		}
		assertPayloadRemarshals(t, p, marshalKeygenSharePayload, unmarshalKeygenSharePayload)
	})
}

func FuzzFROSTNonceCommitmentPayloadUnmarshal(f *testing.F) {
	raw, err := marshalNonceCommitmentPayload(nonceCommitment{
		D: seedFROSTPoint(f),
		E: seedFROSTPoint(f),
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"d":"x","e":"y"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := unmarshalNonceCommitmentPayload(data)
		if err != nil {
			return
		}
		assertPayloadRemarshals(t, p, marshalNonceCommitmentPayload, unmarshalNonceCommitmentPayload)
	})
}

func FuzzFROSTSignPartialPayloadUnmarshal(f *testing.F) {
	raw, err := marshalSignPartialPayload(signPartialPayload{Z: seedFROSTScalar(f)})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"z":"x"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := unmarshalSignPartialPayload(data)
		if err != nil {
			return
		}
		assertPayloadRemarshals(t, p, marshalSignPartialPayload, unmarshalSignPartialPayload)
	})
}

func FuzzFROSTReshareCommitmentsPayloadUnmarshal(f *testing.F) {
	raw, err := marshalReshareCommitmentsPayload(reshareCommitmentsPayload{
		Commitments: [][]byte{seedFROSTPoint(f)},
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"commitments":[]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := unmarshalReshareCommitmentsPayload(data)
		if err != nil {
			return
		}
		assertPayloadRemarshals(t, p, marshalReshareCommitmentsPayload, unmarshalReshareCommitmentsPayload)
	})
}

func FuzzFROSTReshareSharePayloadUnmarshal(f *testing.F) {
	raw, err := marshalReshareSharePayload(reshareSharePayload{Share: seedFROSTScalar(f)})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"share":"x"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := unmarshalReshareSharePayload(data)
		if err != nil {
			return
		}
		assertPayloadRemarshals(t, p, marshalReshareSharePayload, unmarshalReshareSharePayload)
	})
}

func frostKeygenForFuzz(f *testing.F, threshold, n int) map[tss.PartyID]*KeyShare {
	f.Helper()
	session, err := tss.NewSessionID(nil)
	if err != nil {
		f.Fatal(err)
	}
	parties := make([]tss.PartyID, n)
	for i := range parties {
		parties[i] = tss.PartyID(i + 1)
	}
	sessions := make(map[tss.PartyID]*KeygenSession, n)
	messages := make([]tss.Envelope, 0)
	for _, id := range parties {
		kg, out, err := StartKeygen(tss.ThresholdConfig{Threshold: threshold, Parties: parties, Self: id, SessionID: session})
		if err != nil {
			f.Fatal(err)
		}
		sessions[id] = kg
		messages = append(messages, out...)
	}
	for _, env := range messages {
		for _, id := range parties {
			if id == env.From || (env.To != 0 && env.To != id) {
				continue
			}
			if _, err := sessions[id].HandleKeygenMessage(env); err != nil {
				f.Fatal(err)
			}
		}
	}
	out := make(map[tss.PartyID]*KeyShare, n)
	for _, id := range parties {
		share, ok := sessions[id].KeyShare()
		if !ok {
			f.Fatalf("keygen not complete for %d", id)
		}
		out[id] = share
	}
	return out
}

func cloneFROSTKeyShare(in *KeyShare) *KeyShare {
	if in == nil {
		return nil
	}
	out := *in
	out.Parties = append([]tss.PartyID(nil), in.Parties...)
	out.PublicKey = append([]byte(nil), in.PublicKey...)
	out.secret = append([]byte(nil), in.secret...)
	out.GroupCommitments = cloneFROSTByteSlices(in.GroupCommitments)
	out.VerificationShares = append([]VerificationShare(nil), in.VerificationShares...)
	for i := range out.VerificationShares {
		out.VerificationShares[i].PublicKey = append([]byte(nil), in.VerificationShares[i].PublicKey...)
	}
	return &out
}

func cloneFROSTByteSlices(in [][]byte) [][]byte {
	out := make([][]byte, len(in))
	for i := range in {
		out[i] = append([]byte(nil), in[i]...)
	}
	return out
}

func seedFROSTPoint(tb testing.TB) []byte {
	tb.Helper()
	point, err := edcurve.ScalarBaseMultBig(big.NewInt(1))
	if err != nil {
		tb.Fatal(err)
	}
	return point.Bytes()
}

func seedFROSTScalar(tb testing.TB) []byte {
	tb.Helper()
	out, err := scalarBytes(big.NewInt(1))
	if err != nil {
		tb.Fatal(err)
	}
	return out
}

func assertPayloadRemarshals[P any](t *testing.T, p P, marshal func(P) ([]byte, error), unmarshal func([]byte) (P, error)) {
	t.Helper()
	raw, err := marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := unmarshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, again) {
		t.Fatal("payload did not remarshal deterministically")
	}
}
