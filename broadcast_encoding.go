package tss

import (
	"cmp"
	"errors"
	"fmt"
	"slices"

	"github.com/islishude/tss/internal/wire"
)

const (
	broadcastAckWireType            = "tss.broadcast-ack"
	broadcastCertificateWireType    = "tss.broadcast-certificate"
	broadcastAckWireVersion         = 1
	broadcastCertificateWireVersion = 1
)

func broadcastFieldLimits() wire.FieldLimits {
	return wire.FieldLimits{
		"protocol_name":        DefaultMaxProtocolNameBytes,
		"payload_type":         DefaultMaxPayloadTypeBytes,
		"broadcast_signature":  DefaultMaxWireFieldBytes,
		"broadcast_recipients": DefaultMaxParties,
	}
}

// WireType returns the canonical wire type identifier for BroadcastAck.
func (BroadcastAck) WireType() string { return broadcastAckWireType }

// WireVersion returns the wire format version for BroadcastAck.
func (BroadcastAck) WireVersion() uint16 { return broadcastAckWireVersion }

// MarshalBinary encodes the broadcast acknowledgment using canonical TLV.
func (a BroadcastAck) MarshalBinary() ([]byte, error) {
	return wire.Marshal(a, wire.WithFieldLimitsForMarshal(broadcastFieldLimits()))
}

// UnmarshalBinary decodes a canonical broadcast acknowledgment.
func (a *BroadcastAck) UnmarshalBinary(in []byte) error {
	if a == nil {
		return errors.New("nil broadcast ack")
	}
	var decoded BroadcastAck
	if err := wire.Unmarshal(in, &decoded,
		wire.WithFrameLimits(wire.DefaultFrameLimits()),
		wire.WithFieldLimits(broadcastFieldLimits()),
	); err != nil {
		return err
	}
	*a = decoded
	return nil
}

// Validate checks the broadcast acknowledgment's structural invariants.
func (a BroadcastAck) Validate() error {
	if a.Party == BroadcastPartyId {
		return errors.New("broadcast ack party is zero")
	}
	return nil
}

// WireType returns the canonical wire type identifier for BroadcastCertificate.
func (BroadcastCertificate) WireType() string { return broadcastCertificateWireType }

// WireVersion returns the wire format version for BroadcastCertificate.
func (BroadcastCertificate) WireVersion() uint16 { return broadcastCertificateWireVersion }

// BeforeMarshalWire canonicalizes recipient and acknowledgment ordering.
func (c *BroadcastCertificate) BeforeMarshalWire() error {
	if c == nil {
		return errors.New("nil broadcast certificate")
	}
	c.Recipients = SortParties(c.Recipients)
	slices.SortStableFunc(c.Acks, func(a, b BroadcastAck) int {
		return cmp.Compare(a.Party, b.Party)
	})
	return nil
}

// MarshalBinary encodes the broadcast certificate using canonical TLV.
func (c *BroadcastCertificate) MarshalBinary() ([]byte, error) {
	if c == nil {
		return nil, errors.New("nil broadcast certificate")
	}
	return wire.Marshal(c, wire.WithFieldLimitsForMarshal(broadcastFieldLimits()))
}

// UnmarshalBinary decodes a canonical broadcast certificate.
func (c *BroadcastCertificate) UnmarshalBinary(in []byte) error {
	if c == nil {
		return errors.New("nil broadcast certificate")
	}
	if len(in) == 0 {
		return errors.New("empty broadcast certificate")
	}
	var decoded BroadcastCertificate
	if err := wire.Unmarshal(in, &decoded,
		wire.WithFrameLimits(wire.DefaultFrameLimits()),
		wire.WithFieldLimits(broadcastFieldLimits()),
	); err != nil {
		return err
	}
	*c = decoded
	return nil
}

// Validate checks the broadcast certificate's canonical structural invariants.
func (c *BroadcastCertificate) Validate() error {
	if c == nil {
		return errors.New("nil broadcast certificate")
	}
	if c.Protocol == "" {
		return errors.New("broadcast certificate protocol is empty")
	}
	if !c.SessionID.Valid() {
		return errors.New("broadcast certificate session ID is invalid")
	}
	if c.From == BroadcastPartyId {
		return errors.New("broadcast certificate sender is zero")
	}
	if c.PayloadType == "" {
		return errors.New("broadcast certificate payload type is empty")
	}
	if len(c.Recipients) == 0 {
		return errors.New("broadcast certificate recipients are empty")
	}
	if err := wire.ValidateStrictSortedIDs(c.Recipients); err != nil {
		return fmt.Errorf("broadcast certificate recipients: %w", err)
	}
	if len(c.Acks) != len(c.Recipients) {
		return fmt.Errorf("broadcast certificate ack count %d does not match recipient count %d", len(c.Acks), len(c.Recipients))
	}
	for i, ack := range c.Acks {
		if err := ack.Validate(); err != nil {
			return fmt.Errorf("broadcast certificate ack %d: %w", i, err)
		}
		if ack.Party != c.Recipients[i] {
			return fmt.Errorf("broadcast certificate ack party %d out of recipient order at index %d", ack.Party, i)
		}
		if ack.PayloadHash != c.PayloadHash {
			return fmt.Errorf("broadcast certificate ack party %d has mismatched payload hash", ack.Party)
		}
		if ack.EnvelopeDigest != c.EnvelopeDigest {
			return fmt.Errorf("broadcast certificate ack party %d has mismatched envelope digest", ack.Party)
		}
	}
	return nil
}
