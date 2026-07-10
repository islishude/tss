package secret

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestSignedIntLifecycle(t *testing.T) {
	t.Parallel()

	magnitude := []byte{0, 0, 0, 7}
	value, err := NewSignedInt(true, magnitude, len(magnitude))
	if err != nil {
		t.Fatal(err)
	}
	magnitude[len(magnitude)-1] = 9
	if got := value.FixedMagnitude(); got[len(got)-1] != 7 {
		t.Fatal("constructor retained caller-owned magnitude")
	}

	clone := value.Clone()
	if !value.Equal(clone) {
		t.Fatal("clone is not equal")
	}
	cloneMagnitude := clone.FixedMagnitude()
	cloneMagnitude[len(cloneMagnitude)-1] = 8
	if !value.Equal(clone) {
		t.Fatal("FixedMagnitude exposed internal storage")
	}

	selected, err := value.SelectBySign([]byte{1, 2}, []byte{3, 4})
	if err != nil {
		t.Fatal(err)
	}
	if selected[0] != 3 || selected[1] != 4 {
		t.Fatal("negative value selected non-negative input")
	}

	clone.Destroy()
	if clone.FixedLen() != 0 || clone.FixedMagnitude() != nil {
		t.Fatal("Destroy retained secret magnitude")
	}
	if _, err := clone.SelectBySign([]byte{1}, []byte{2}); err == nil {
		t.Fatal("destroyed SignedInt remained usable")
	}
	value.Destroy()
}

func TestSignedIntRejectsInvalidInputs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		negative  bool
		magnitude []byte
		fixedLen  int
	}{
		{name: "zero length", magnitude: nil, fixedLen: 0},
		{name: "short", magnitude: []byte{1}, fixedLen: 2},
		{name: "long", magnitude: []byte{1, 2, 3}, fixedLen: 2},
		{name: "negative zero", negative: true, magnitude: []byte{0, 0}, fixedLen: 2},
	}
	for i := range tests {
		tc := tests[i]
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewSignedInt(tc.negative, tc.magnitude, tc.fixedLen); err == nil {
				t.Fatal("NewSignedInt accepted invalid input")
			}
		})
	}
}

func TestSignedIntRedactsAndRejectsSerialization(t *testing.T) {
	t.Parallel()

	value, err := NewSignedInt(false, []byte{0, 1}, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer value.Destroy()
	copied := *value

	for _, tc := range []struct {
		name  string
		value any
	}{
		{name: "pointer", value: value},
		{name: "value", value: copied},
	} {
		for _, format := range []string{"%v", "%+v", "%#v", "%x"} {
			if got := fmt.Sprintf(format, tc.value); got != signedIntRedacted {
				t.Fatalf("%s SignedInt formatted with %s without redaction", tc.name, format)
			}
		}
	}
	if _, err := json.Marshal(value); err == nil {
		t.Fatal("JSON encoding succeeded")
	}
	var decoded SignedInt
	if err := json.Unmarshal([]byte(`{}`), &decoded); err == nil {
		t.Fatal("JSON decoding succeeded")
	}
	if _, err := value.MarshalBinary(); err == nil {
		t.Fatal("binary encoding succeeded")
	}
	if err := decoded.UnmarshalBinary([]byte{1}); err == nil {
		t.Fatal("binary decoding succeeded")
	}
	if _, err := value.SelectBySign([]byte{1}, []byte{1, 2}); err == nil {
		t.Fatal("SelectBySign accepted mismatched inputs")
	}
}
