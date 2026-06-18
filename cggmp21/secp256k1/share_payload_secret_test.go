package secp256k1

import (
	"bytes"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/wire"
)

func TestDKGSharePayloadsRoundTripSecretScalars(t *testing.T) {
	t.Parallel()

	planHash := bytes.Repeat([]byte{0x42}, 32)
	commitHash := bytes.Repeat([]byte{0x24}, 32)
	tests := []struct {
		name string
		run  func(*secret.Scalar) error
	}{
		{
			name: "keygen",
			run: func(s *secret.Scalar) error {
				raw, err := marshalKeygenSharePayload(keygenSharePayload{Share: s, PlanHash: planHash})
				if err != nil {
					return err
				}
				decoded, err := unmarshalKeygenSharePayload(raw)
				if err != nil {
					return err
				}
				if !decoded.Share.Equal(s) {
					t.Fatal("decoded keygen share mismatch")
				}
				raw2, err := marshalKeygenSharePayload(decoded)
				if err != nil {
					return err
				}
				if !bytes.Equal(raw, raw2) {
					t.Fatal("keygen share re-encoded differently")
				}
				return nil
			},
		},
		{
			name: "refresh",
			run: func(s *secret.Scalar) error {
				raw, err := marshalRefreshSharePayload(refreshSharePayload{Share: s, PlanHash: planHash})
				if err != nil {
					return err
				}
				decoded, err := unmarshalRefreshSharePayload(raw)
				if err != nil {
					return err
				}
				if !decoded.Share.Equal(s) {
					t.Fatal("decoded refresh share mismatch")
				}
				raw2, err := marshalRefreshSharePayload(decoded)
				if err != nil {
					return err
				}
				if !bytes.Equal(raw, raw2) {
					t.Fatal("refresh share re-encoded differently")
				}
				return nil
			},
		},
		{
			name: "reshare",
			run: func(s *secret.Scalar) error {
				raw, err := marshalReshareSharePayload(reshareSharePayload{
					Dealer:               1,
					Receiver:             2,
					Share:                s,
					DealerCommitmentHash: commitHash,
					PlanHash:             planHash,
				})
				if err != nil {
					return err
				}
				decoded, err := unmarshalReshareSharePayload(raw)
				if err != nil {
					return err
				}
				if !decoded.Share.Equal(s) {
					t.Fatal("decoded reshare share mismatch")
				}
				raw2, err := marshalReshareSharePayload(decoded)
				if err != nil {
					return err
				}
				if !bytes.Equal(raw, raw2) {
					t.Fatal("reshare share re-encoded differently")
				}
				return nil
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := tc.run(testSecretScalar(t, 7)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDKGSharePayloadsRejectOldBigPosEncoding(t *testing.T) {
	t.Parallel()

	planHash := bytes.Repeat([]byte{0x52}, 32)
	commitHash := bytes.Repeat([]byte{0x25}, 32)
	tests := []struct {
		name string
		raw  func(t *testing.T) []byte
		run  func([]byte) error
	}{
		{
			name: "keygen",
			raw: func(t *testing.T) []byte {
				return mustMarshalFields(t, keygenSharePayloadWireType, []wire.Field{
					{Tag: 1, Value: []byte{0x01}},
					{Tag: 2, Value: planHash},
				})
			},
			run: func(raw []byte) error {
				_, err := unmarshalKeygenSharePayload(raw)
				return err
			},
		},
		{
			name: "refresh",
			raw: func(t *testing.T) []byte {
				return mustMarshalFields(t, refreshSharePayloadWireType, []wire.Field{
					{Tag: 1, Value: []byte{0x01}},
					{Tag: 2, Value: planHash},
				})
			},
			run: func(raw []byte) error {
				_, err := unmarshalRefreshSharePayload(raw)
				return err
			},
		},
		{
			name: "reshare",
			raw: func(t *testing.T) []byte {
				return mustMarshalFields(t, reshareSharePayloadWireType, []wire.Field{
					{Tag: 1, Value: wire.Uint32(1)},
					{Tag: 2, Value: wire.Uint32(2)},
					{Tag: 3, Value: []byte{0x01}},
					{Tag: 4, Value: commitHash},
					{Tag: 5, Value: planHash},
				})
			},
			run: func(raw []byte) error {
				_, err := unmarshalReshareSharePayload(raw)
				return err
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := tc.run(tc.raw(t)); err == nil {
				t.Fatal("accepted old bigpos share encoding")
			}
		})
	}
}

func TestDKGSharePayloadsRejectMalformedSecretScalars(t *testing.T) {
	t.Parallel()

	planHash := bytes.Repeat([]byte{0x62}, 32)
	commitHash := bytes.Repeat([]byte{0x26}, 32)
	outOfRange, err := secret.NewScalar(orderBytesForTest(), 32)
	if err != nil {
		t.Fatal(err)
	}
	zero, err := secret.NewScalar([]byte{0}, 32)
	if err != nil {
		t.Fatal(err)
	}

	scalarCases := []struct {
		name  string
		share *secret.Scalar
	}{
		{name: "nil", share: nil},
		{name: "out_of_range", share: outOfRange},
	}
	for _, tc := range scalarCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := marshalKeygenSharePayload(keygenSharePayload{Share: tc.share, PlanHash: planHash}); err == nil {
				t.Fatal("keygen accepted malformed scalar")
			}
			if _, err := marshalRefreshSharePayload(refreshSharePayload{Share: tc.share, PlanHash: planHash}); err == nil {
				t.Fatal("refresh accepted malformed scalar")
			}
			if _, err := marshalReshareSharePayload(reshareSharePayload{
				Dealer:               1,
				Receiver:             2,
				Share:                tc.share,
				DealerCommitmentHash: commitHash,
				PlanHash:             planHash,
			}); err == nil {
				t.Fatal("reshare accepted malformed scalar")
			}
		})
	}

	t.Run("zero_refresh_delta", func(t *testing.T) {
		t.Parallel()
		if _, err := marshalKeygenSharePayload(keygenSharePayload{Share: zero, PlanHash: planHash}); err == nil {
			t.Fatal("keygen accepted zero scalar")
		}
		raw, err := marshalRefreshSharePayload(refreshSharePayload{Share: zero, PlanHash: planHash})
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := unmarshalRefreshSharePayload(raw)
		if err != nil {
			t.Fatal(err)
		}
		if !decoded.Share.Equal(zero) {
			t.Fatal("decoded refresh zero delta mismatch")
		}
		if _, err := marshalReshareSharePayload(reshareSharePayload{
			Dealer:               1,
			Receiver:             2,
			Share:                zero,
			DealerCommitmentHash: commitHash,
			PlanHash:             planHash,
		}); err == nil {
			t.Fatal("reshare accepted zero scalar")
		}
	})

	for _, size := range []int{31, 33} {
		t.Run("wire_length", func(t *testing.T) {
			t.Parallel()
			raw := mustMarshalFields(t, keygenSharePayloadWireType, []wire.Field{
				{Tag: 1, Value: make([]byte, size)},
				{Tag: 2, Value: planHash},
			})
			if _, err := unmarshalKeygenSharePayload(raw); err == nil {
				t.Fatal("keygen accepted wrong-length scalar")
			}
			raw = mustMarshalFields(t, refreshSharePayloadWireType, []wire.Field{
				{Tag: 1, Value: make([]byte, size)},
				{Tag: 2, Value: planHash},
			})
			if _, err := unmarshalRefreshSharePayload(raw); err == nil {
				t.Fatal("refresh accepted wrong-length scalar")
			}
			raw = mustMarshalFields(t, reshareSharePayloadWireType, []wire.Field{
				{Tag: 1, Value: wire.Uint32(1)},
				{Tag: 2, Value: wire.Uint32(2)},
				{Tag: 3, Value: make([]byte, size)},
				{Tag: 4, Value: commitHash},
				{Tag: 5, Value: planHash},
			})
			if _, err := unmarshalReshareSharePayload(raw); err == nil {
				t.Fatal("reshare accepted wrong-length scalar")
			}
		})
	}
}

func mustMarshalFields(t *testing.T, wireType string, fields []wire.Field) []byte {
	t.Helper()
	raw, err := wire.MarshalFields(1, wireType, fields)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func orderBytesForTest() []byte {
	return secp.Order().FillBytes(make([]byte, 32))
}
