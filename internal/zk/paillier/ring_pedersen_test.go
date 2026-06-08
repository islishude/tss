package paillier

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/islishude/tss/internal/testutil"
)

func TestRingPedersenProofChecks(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping crypto proof test in short mode")
	}
	sk := testPaillierKey(t, 512)
	params, lambda, err := GenerateRingPedersenParams(nil, sk)
	if err != nil {
		t.Fatal(err)
	}
	paramsBytes, err := MarshalRingPedersenParams(params)
	if err != nil {
		t.Fatal(err)
	}
	domain := []byte("ring pedersen")
	party := uint32(3)
	proof, err := ProveRingPedersen(nil, domain, sk, params, lambda, party)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyRingPedersen(domain, params, party, proof) {
		t.Fatal("Ring-Pedersen proof did not verify")
	}
	if VerifyRingPedersen([]byte("other"), params, party, proof) {
		t.Fatal("Ring-Pedersen proof verified under wrong domain")
	}
	if VerifyRingPedersen(domain, params, party+1, proof) {
		t.Fatal("Ring-Pedersen proof verified under wrong party")
	}
	decodedParams, err := UnmarshalRingPedersenParams(paramsBytes)
	if err != nil {
		t.Fatal(err)
	}
	if decodedParams.N.Cmp(params.N) != 0 || decodedParams.S.Cmp(params.S) != 0 || decodedParams.T.Cmp(params.T) != 0 {
		t.Fatal("Ring-Pedersen parameters did not round-trip")
	}

	nLen := modulusBytes(params.N)
	t.Run("invalid params", func(t *testing.T) {
		bad := &RingPedersenParams{N: params.N, S: big.NewInt(1), T: params.T}
		if ValidateRingPedersenParams(bad) == nil {
			t.Fatal("degenerate Ring-Pedersen parameters validated")
		}
		if VerifyRingPedersen(domain, bad, party, proof) {
			t.Fatal("Ring-Pedersen proof verified against invalid parameters")
		}
	})
	t.Run("out of range response", func(t *testing.T) {
		tampered := cloneRingPedersenProof(proof)
		tampered.Responses[0] = fixedModNBytes(params.N, nLen)
		if VerifyRingPedersen(domain, params, party, tampered) {
			t.Fatal("Ring-Pedersen proof with out-of-range response verified")
		}
	})
	t.Run("tamper", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			mutate func(*RingPedersenProof)
		}{
			{name: "commitment", mutate: func(p *RingPedersenProof) { p.Commitments[0][len(p.Commitments[0])-1] ^= 1 }},
			{name: "challenge", mutate: func(p *RingPedersenProof) { p.Challenges[0] ^= 1 }},
			{name: "response", mutate: func(p *RingPedersenProof) { p.Responses[0][len(p.Responses[0])-1] ^= 1 }},
		} {
			t.Run(tc.name, func(t *testing.T) {
				tampered := cloneRingPedersenProof(proof)
				tc.mutate(tampered)
				if VerifyRingPedersen(domain, params, party, tampered) {
					t.Fatal("tampered Ring-Pedersen proof verified")
				}
			})
		}
	})
}

func assertRingPedersenProofRoundTrip(t *testing.T, proof *RingPedersenProof) {
	t.Helper()
	raw, err := Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalRingPedersenProof(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, again) {
		t.Fatal("Ring-Pedersen proof encoding is not deterministic")
	}
	if _, err := UnmarshalRingPedersenProof(append(raw, 0)); err == nil {
		t.Fatal("Ring-Pedersen proof accepted trailing bytes")
	}
}

func cloneRingPedersenProof(in *RingPedersenProof) *RingPedersenProof {
	out := *in
	out.TranscriptHash = append([]byte(nil), in.TranscriptHash...)
	out.Commitments = testutil.CloneByteSlices(in.Commitments)
	out.Challenges = append([]byte(nil), in.Challenges...)
	out.Responses = testutil.CloneByteSlices(in.Responses)
	return &out
}
