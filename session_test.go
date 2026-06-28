package tss

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func TestSessionIDMarshalText(t *testing.T) {
	var zero SessionID

	var sequential SessionID
	for i := range sequential {
		sequential[i] = byte(i)
	}

	tests := []struct {
		name string
		id   SessionID
		want string
	}{
		{
			name: "zero",
			id:   zero,
			want: strings.Repeat("00", sessionIDSize),
		},
		{
			name: "sequential bytes",
			id:   sequential,
			want: hex.EncodeToString(sequential[:]),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.id.MarshalText()
			if err != nil {
				t.Fatalf("MarshalText() error = %v", err)
			}
			if string(got) != tt.want {
				t.Fatalf("MarshalText() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSessionIDUnmarshalText(t *testing.T) {
	var sequential SessionID
	for i := range sequential {
		sequential[i] = byte(i)
	}

	validLower := hex.EncodeToString(sequential[:])
	validUpper := strings.ToUpper(validLower)

	tests := []struct {
		name        string
		text        string
		want        SessionID
		wantErr     bool
		nilReceiver bool
	}{
		{
			name: "valid lowercase hex",
			text: validLower,
			want: sequential,
		},
		{
			name: "valid uppercase hex",
			text: validUpper,
			want: sequential,
		},
		{
			name:    "too short",
			text:    validLower[:len(validLower)-2],
			wantErr: true,
		},
		{
			name:    "too long",
			text:    validLower + "00",
			wantErr: true,
		},
		{
			name:    "invalid hex character",
			text:    validLower[:10] + "zz" + validLower[12:],
			wantErr: true,
		},
		{
			name:        "nil receiver",
			text:        validLower,
			wantErr:     true,
			nilReceiver: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.nilReceiver {
				var id *SessionID
				err := id.UnmarshalText([]byte(tt.text))
				if (err != nil) != tt.wantErr {
					t.Fatalf("UnmarshalText() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}

			var got SessionID
			err := got.UnmarshalText([]byte(tt.text))
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalText() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if got != tt.want {
				t.Fatalf("UnmarshalText() = %x, want %x", got[:], tt.want[:])
			}
		})
	}
}

func TestSessionIDUnmarshalTextDoesNotMutateOnError(t *testing.T) {
	var original SessionID
	for i := range original {
		original[i] = byte(255 - i)
	}

	tests := []struct {
		name string
		text string
	}{
		{
			name: "invalid length",
			text: "abc",
		},
		{
			name: "invalid hex with correct length",
			text: strings.Repeat("0", sessionIDHexSize-1) + "z",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := original

			err := got.UnmarshalText([]byte(tt.text))
			if err == nil {
				t.Fatal("UnmarshalText() error = nil, want non-nil")
			}

			if got != original {
				t.Fatalf("UnmarshalText() mutated receiver on error: got %x, want %x", got[:], original[:])
			}
		})
	}
}

func TestSessionIDBytesReturnsCopy(t *testing.T) {
	var id SessionID
	for i := range id {
		id[i] = byte(i)
	}

	got := id.Bytes()
	if !bytes.Equal(got, id[:]) {
		t.Fatalf("Bytes() = %x, want %x", got, id[:])
	}

	got[0] ^= 0xff
	if got[0] == id[0] {
		t.Fatal("Bytes() returned a slice aliasing the SessionID storage")
	}
}
