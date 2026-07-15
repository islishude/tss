package wire

import (
	"bytes"
	"errors"
	"testing"
)

// ---- test types for MessageMarshaler / MessageUnmarshaler ----

// msgHookMessage is a simple message that implements both MessageMarshaler
// and MessageUnmarshaler by delegating to an internal DTO.
type msgHookMessage struct {
	Value uint16
}

func (m msgHookMessage) WireType() string    { return "wire.test.msghook" }
func (m msgHookMessage) WireVersion() uint16 { return 1 }

// msgHookDTO mirrors msgHookMessage with wire tags.
type msgHookDTO struct {
	Value uint16 `wire:"1,u16"`
}

func (msgHookDTO) WireType() string    { return "wire.test.msghook" }
func (msgHookDTO) WireVersion() uint16 { return 1 }

func (m msgHookMessage) MarshalWireMessage(opts ...MarshalOption) ([]byte, error) {
	dto := msgHookDTO(m)
	return Marshal(dto, opts...)
}

func (m *msgHookMessage) UnmarshalWireMessage(in []byte, opts ...UnmarshalOption) error {
	var dto msgHookDTO
	if err := Unmarshal(in, &dto, opts...); err != nil {
		return err
	}
	m.Value = dto.Value
	return nil
}

// msgHookErrorMarshal returns an error from MarshalWireMessage.
type msgHookErrorMarshal struct{}

func (msgHookErrorMarshal) WireType() string    { return "wire.test.msghook.err.marshal" }
func (msgHookErrorMarshal) WireVersion() uint16 { return 1 }

var errMarshalHook = errors.New("marshal hook error")

func (msgHookErrorMarshal) MarshalWireMessage(opts ...MarshalOption) ([]byte, error) {
	return nil, errMarshalHook
}

// msgHookNilMarshal returns nil bytes without error.
type msgHookNilMarshal struct{}

func (msgHookNilMarshal) WireType() string    { return "wire.test.msghook.nil" }
func (msgHookNilMarshal) WireVersion() uint16 { return 1 }

func (msgHookNilMarshal) MarshalWireMessage(opts ...MarshalOption) ([]byte, error) {
	return nil, nil
}

// msgHookErrorUnmarshal returns an error from UnmarshalWireMessage.
type msgHookErrorUnmarshal struct {
	Value uint16
}

func (msgHookErrorUnmarshal) WireType() string    { return "wire.test.msghook" }
func (msgHookErrorUnmarshal) WireVersion() uint16 { return 1 }

var errUnmarshalHook = errors.New("unmarshal hook error")

func (m msgHookErrorUnmarshal) MarshalWireMessage(opts ...MarshalOption) ([]byte, error) {
	dto := msgHookDTO(m)
	return Marshal(dto, opts...)
}

func (m *msgHookErrorUnmarshal) UnmarshalWireMessage(in []byte, opts ...UnmarshalOption) error {
	return errUnmarshalHook
}

// msgHookWithBeforeAfter implements BeforeMarshaler and AfterUnmarshaler
// alongside MessageMarshaler / MessageUnmarshaler.
type msgHookWithBeforeAfter struct {
	Value        uint16
	BeforeCalled bool
	AfterCalled  bool
}

func (m msgHookWithBeforeAfter) WireType() string    { return "wire.test.msghook" }
func (m msgHookWithBeforeAfter) WireVersion() uint16 { return 1 }

func (m *msgHookWithBeforeAfter) BeforeMarshalWire() error {
	m.BeforeCalled = true
	return nil
}

func (m *msgHookWithBeforeAfter) AfterUnmarshalWire() error {
	m.AfterCalled = true
	return nil
}

func (m msgHookWithBeforeAfter) MarshalWireMessage(opts ...MarshalOption) ([]byte, error) {
	dto := msgHookDTO{Value: m.Value}
	return Marshal(dto, opts...)
}

func (m *msgHookWithBeforeAfter) UnmarshalWireMessage(in []byte, opts ...UnmarshalOption) error {
	var dto msgHookDTO
	if err := Unmarshal(in, &dto, opts...); err != nil {
		return err
	}
	m.Value = dto.Value
	return nil
}

// msgHookWithValidate implements Validator alongside MessageMarshaler.
type msgHookWithValidate struct {
	Value uint16
}

func (m msgHookWithValidate) WireType() string    { return "wire.test.msghook" }
func (m msgHookWithValidate) WireVersion() uint16 { return 1 }

func (m msgHookWithValidate) Validate() error {
	if m.Value == 0 {
		return errSentinel
	}
	return nil
}

func (m msgHookWithValidate) MarshalWireMessage(opts ...MarshalOption) ([]byte, error) {
	dto := msgHookDTO(m)
	return Marshal(dto, opts...)
}

func (m *msgHookWithValidate) UnmarshalWireMessage(in []byte, opts ...UnmarshalOption) error {
	var dto msgHookDTO
	if err := Unmarshal(in, &dto, opts...); err != nil {
		return err
	}
	m.Value = dto.Value
	return nil
}

// msgHookWithOptions passes MarshalOptions through to the DTO.
type msgHookWithOptions struct {
	Payload []byte
}

func (m msgHookWithOptions) WireType() string    { return "wire.test.msghook.opts" }
func (m msgHookWithOptions) WireVersion() uint16 { return 1 }

type msgHookWithOptionsDTO struct {
	Payload []byte `wire:"1,bytes,max_bytes=field"`
}

func (msgHookWithOptionsDTO) WireType() string    { return "wire.test.msghook.opts" }
func (msgHookWithOptionsDTO) WireVersion() uint16 { return 1 }

func (m msgHookWithOptions) MarshalWireMessage(opts ...MarshalOption) ([]byte, error) {
	dto := msgHookWithOptionsDTO(m)
	return Marshal(dto, opts...)
}

func (m *msgHookWithOptions) UnmarshalWireMessage(in []byte, opts ...UnmarshalOption) error {
	var dto msgHookWithOptionsDTO
	if err := Unmarshal(in, &dto, opts...); err != nil {
		return err
	}
	m.Payload = dto.Payload
	return nil
}

// notMessage is a struct that does NOT implement Message.
type notMessage struct {
	Value uint16 `wire:"1,u16"`
}

func (notMessage) MarshalWireMessage(opts ...MarshalOption) ([]byte, error) {
	return Uint16(42), nil
}

// msgHookPtrOnly implements MessageMarshaler only on the pointer receiver,
// testing the fallback path in Marshal (v.Addr().Interface()).
type msgHookPtrOnly struct {
	Value uint16
}

func (msgHookPtrOnly) WireType() string    { return "wire.test.msghook" }
func (msgHookPtrOnly) WireVersion() uint16 { return 1 }

func (m *msgHookPtrOnly) MarshalWireMessage(opts ...MarshalOption) ([]byte, error) {
	dto := msgHookDTO{Value: m.Value}
	return Marshal(dto, opts...)
}

func (m *msgHookPtrOnly) UnmarshalWireMessage(in []byte, opts ...UnmarshalOption) error {
	var dto msgHookDTO
	if err := Unmarshal(in, &dto, opts...); err != nil {
		return err
	}
	m.Value = dto.Value
	return nil
}

type rawMessageHook struct {
	raw []byte
}

func (rawMessageHook) WireType() string    { return "wire.test.rawhook" }
func (rawMessageHook) WireVersion() uint16 { return 1 }

func (m rawMessageHook) MarshalWireMessage(opts ...MarshalOption) ([]byte, error) {
	return bytes.Clone(m.raw), nil
}

type acceptingMessageHook struct {
	Value uint16
}

func (acceptingMessageHook) WireType() string    { return "wire.test.rawhook" }
func (acceptingMessageHook) WireVersion() uint16 { return 1 }

func (m *acceptingMessageHook) UnmarshalWireMessage(in []byte, opts ...UnmarshalOption) error {
	m.Value = 42
	return nil
}

func rawHookFrame(version uint16, fields []Field) []byte {
	out := bytes.Clone(magic)
	out = AppendUint16(out, uint16(len("wire.test.rawhook")))
	out = append(out, "wire.test.rawhook"...)
	out = AppendUint16(out, version)
	out = AppendUint16(out, uint16(len(fields)))
	for _, field := range fields {
		out = AppendUint16(out, field.Tag)
		out = AppendUint32(out, uint32(len(field.Value)))
		out = append(out, field.Value...)
	}
	return out
}

// ---- Marshal tests ----

func TestMessageMarshalerCalled(t *testing.T) {
	t.Parallel()

	orig := msgHookMessage{Value: 1234}
	raw, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}

	var decoded msgHookMessage
	if err := Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Value != 1234 {
		t.Fatalf("got %d, want 1234", decoded.Value)
	}
}

func TestMessageMarshalerNilReturn(t *testing.T) {
	t.Parallel()

	msg := msgHookNilMarshal{}
	_, err := Marshal(msg)
	if err == nil {
		t.Fatal("expected error for nil return from MarshalWireMessage")
	}
	if !stringsContains(err.Error(), "nil") {
		t.Fatalf("expected nil-related error, got: %v", err)
	}
}

func TestMessageMarshalerErrorReturn(t *testing.T) {
	t.Parallel()

	msg := msgHookErrorMarshal{}
	_, err := Marshal(msg)
	if err == nil {
		t.Fatal("expected error from MarshalWireMessage")
	}
	if !errors.Is(err, errMarshalHook) {
		t.Fatalf("expected errMarshalHook, got: %v", err)
	}
}

func TestBeforeMarshalCalledBeforeHook(t *testing.T) {
	t.Parallel()

	orig := &msgHookWithBeforeAfter{Value: 5}
	raw, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	if !orig.BeforeCalled {
		t.Fatal("BeforeMarshalWire was not called")
	}

	var decoded msgHookWithBeforeAfter
	if err := Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if !decoded.AfterCalled {
		t.Fatal("AfterUnmarshalWire was not called")
	}
}

func TestValidateCalledBeforeMarshalHook(t *testing.T) {
	t.Parallel()

	// Validation should fail for zero value.
	msg := msgHookWithValidate{Value: 0}
	_, err := Marshal(msg)
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !errors.Is(err, errSentinel) {
		t.Fatalf("expected errSentinel from Validate, got: %v", err)
	}

	// Validation should pass for non-zero value.
	msg.Value = 99
	raw, err := Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	var decoded msgHookWithValidate
	if err := Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Value != 99 {
		t.Fatalf("got %d, want 99", decoded.Value)
	}
}

func TestMarshalOptionsPassedThroughToHook(t *testing.T) {
	t.Parallel()

	// Payload that exceeds the limit should fail.
	msg := msgHookWithOptions{Payload: bytes.Repeat([]byte{1}, 200)}

	limits := FieldLimits{"field": 100}
	_, err := Marshal(msg, WithFieldLimitsForMarshal(limits))
	if err == nil {
		t.Fatal("expected max_bytes violation error")
	}

	// Payload within limit should succeed.
	msg.Payload = bytes.Repeat([]byte{1}, 50)
	raw, err := Marshal(msg, WithFieldLimitsForMarshal(limits))
	if err != nil {
		t.Fatal(err)
	}

	var decoded msgHookWithOptions
	umLimits := FieldLimits{"field": 100}
	if err := Unmarshal(raw, &decoded, WithFieldLimits(umLimits)); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Payload) != 50 {
		t.Fatalf("got %d bytes, want 50", len(decoded.Payload))
	}
}

func TestMessageMarshalerPointerReceiverFallback(t *testing.T) {
	t.Parallel()

	// msgHookPtrOnly implements MessageMarshaler only on *msgHookPtrOnly.
	// Both value and pointer forms should use the custom codec.
	origVal := msgHookPtrOnly{Value: 99}
	raw, err := Marshal(origVal) // value — should fall back to v.Addr().Interface()
	if err != nil {
		t.Fatal(err)
	}

	var decoded msgHookPtrOnly
	if err := Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Value != 99 {
		t.Fatalf("value form: got %d, want 99", decoded.Value)
	}

	// Pointer form should also work.
	origPtr := &msgHookPtrOnly{Value: 77}
	raw2, err := Marshal(origPtr) // pointer — direct match
	if err != nil {
		t.Fatal(err)
	}

	var decoded2 msgHookPtrOnly
	if err := Unmarshal(raw2, &decoded2); err != nil {
		t.Fatal(err)
	}
	if decoded2.Value != 77 {
		t.Fatalf("pointer form: got %d, want 77", decoded2.Value)
	}
}

func TestMarshalRejectsNonMessageEvenWithHook(t *testing.T) {
	t.Parallel()

	msg := notMessage{Value: 42}
	_, err := Marshal(msg)
	if err == nil {
		t.Fatal("expected error for non-Message type")
	}
	if !stringsContains(err.Error(), "Message") {
		t.Fatalf("expected Message-related error, got: %v", err)
	}
}

func TestMessageMarshalerOutputReceivesCanonicalSelfCheck(t *testing.T) {
	t.Parallel()

	wrongType, err := MarshalFields(1, "wire.test.other", []Field{{Tag: 1, Value: []byte{1}}})
	if err != nil {
		t.Fatal(err)
	}
	wrongVersion, err := MarshalFields(2, "wire.test.rawhook", []Field{{Tag: 1, Value: []byte{1}}})
	if err != nil {
		t.Fatal(err)
	}
	valid, err := MarshalFields(1, "wire.test.rawhook", []Field{{Tag: 1, Value: []byte{1}}})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		raw  []byte
	}{
		{name: "wrong type", raw: wrongType},
		{name: "wrong version", raw: wrongVersion},
		{name: "tag zero", raw: rawHookFrame(1, []Field{{Tag: 0, Value: []byte{1}}})},
		{name: "duplicate tag", raw: rawHookFrame(1, []Field{{Tag: 1, Value: []byte{1}}, {Tag: 1, Value: []byte{2}}})},
		{name: "unsorted tag", raw: rawHookFrame(1, []Field{{Tag: 2, Value: []byte{1}}, {Tag: 1, Value: []byte{2}}})},
		{name: "trailing bytes", raw: append(bytes.Clone(valid), 0xff)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := Marshal(rawMessageHook{raw: tc.raw}); err == nil {
				t.Fatal("expected invalid hook output to be rejected")
			}
		})
	}
}

// ---- Unmarshal tests ----

func TestMessageUnmarshalerCalled(t *testing.T) {
	t.Parallel()

	orig := msgHookMessage{Value: 5678}
	raw, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}

	var decoded msgHookMessage
	if err := Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Value != 5678 {
		t.Fatalf("got %d, want 5678", decoded.Value)
	}
}

func TestMessageUnmarshalerErrorReturn(t *testing.T) {
	t.Parallel()

	orig := msgHookErrorUnmarshal{Value: 10}
	raw, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}

	var decoded msgHookErrorUnmarshal
	err = Unmarshal(raw, &decoded)
	if err == nil {
		t.Fatal("expected error from UnmarshalWireMessage")
	}
	if !errors.Is(err, errUnmarshalHook) {
		t.Fatalf("expected errUnmarshalHook, got: %v", err)
	}
}

func TestMessageUnmarshalerFailAtomic(t *testing.T) {
	t.Parallel()

	orig := msgHookErrorUnmarshal{Value: 10}
	raw, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}

	decoded := msgHookErrorUnmarshal{Value: 99}
	err = Unmarshal(raw, &decoded)
	if err == nil {
		t.Fatal("expected error from UnmarshalWireMessage")
	}
	// Original dst must be unchanged.
	if decoded.Value != 99 {
		t.Fatalf("dst was modified on failure: got %d, want 99", decoded.Value)
	}
}

func TestMessageUnmarshalerInputReceivesFramePreflight(t *testing.T) {
	t.Parallel()

	malformed := rawHookFrame(1, []Field{{Tag: 0, Value: []byte{1}}})
	decoded := acceptingMessageHook{Value: 99}
	if err := Unmarshal(malformed, &decoded); err == nil {
		t.Fatal("expected malformed frame to be rejected before hook")
	}
	if decoded.Value != 99 {
		t.Fatalf("destination changed on frame rejection: %d", decoded.Value)
	}

	valid, err := MarshalFields(1, "wire.test.rawhook", []Field{{Tag: 1, Value: []byte{1}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := Unmarshal(valid, &decoded, WithFrameLimits(FrameLimits{
		MaxTotalBytes: len(valid) - 1,
	})); err == nil {
		t.Fatal("expected partial frame limit to reject oversized hook input")
	}
}

func TestAfterUnmarshalCalledAfterHook(t *testing.T) {
	t.Parallel()

	orig := &msgHookWithBeforeAfter{Value: 7}
	raw, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}

	var decoded msgHookWithBeforeAfter
	if err := Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if !decoded.AfterCalled {
		t.Fatal("AfterUnmarshalWire was not called after MessageUnmarshaler")
	}
	if decoded.Value != 7 {
		t.Fatalf("got %d, want 7", decoded.Value)
	}
}

func TestValidateCalledAfterUnmarshalHook(t *testing.T) {
	t.Parallel()

	// Valid message.
	orig := msgHookWithValidate{Value: 100}
	raw, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}

	var decoded msgHookWithValidate
	if err := Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Value != 100 {
		t.Fatalf("got %d, want 100", decoded.Value)
	}
}

func TestUnmarshalOptionsPassedThroughToHook(t *testing.T) {
	t.Parallel()

	limits := FieldLimits{"field": 100}
	msg := msgHookWithOptions{Payload: []byte("hello")}
	raw, err := Marshal(msg, WithFieldLimitsForMarshal(limits))
	if err != nil {
		t.Fatal(err)
	}

	// Unmarshal with limit that is too small should fail.
	smallLimits := FieldLimits{"field": 2}
	var decoded msgHookWithOptions
	err = Unmarshal(raw, &decoded, WithFieldLimits(smallLimits))
	if err == nil {
		t.Fatal("expected max_bytes violation on unmarshal")
	}

	// Unmarshal with generous limit should succeed.
	if err := Unmarshal(raw, &decoded, WithFieldLimits(limits)); err != nil {
		t.Fatal(err)
	}
	if string(decoded.Payload) != "hello" {
		t.Fatalf("got %q, want %q", decoded.Payload, "hello")
	}
}

func TestHookTypeVersionMismatchFails(t *testing.T) {
	t.Parallel()

	// Marshal a msgHookDTO manually with wrong type so the hook's
	// inner Unmarshal(DTO) will catch the type mismatch.
	raw, err := MarshalFields(99, "wrong.type.id", []Field{
		{Tag: 1, Value: Uint16(42)},
	})
	if err != nil {
		t.Fatal(err)
	}

	var decoded msgHookMessage
	err = Unmarshal(raw, &decoded)
	if err == nil {
		t.Fatal("expected type mismatch error from DTO unmarshal inside hook")
	}
}

func TestNonPointerDstFails(t *testing.T) {
	t.Parallel()

	var decoded msgHookMessage
	err := Unmarshal(nil, decoded)
	if err == nil {
		t.Fatal("expected error for non-pointer dst")
	}
	if !stringsContains(err.Error(), "pointer") {
		t.Fatalf("expected pointer-related error, got: %v", err)
	}
}

// ---- helpers ----

func stringsContains(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
