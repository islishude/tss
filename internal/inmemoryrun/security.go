// Package inmemoryrun provides a private authenticated router for production
// helpers that deliberately execute a complete multi-party protocol in one
// process. It is not a replacement for an application transport.
package inmemoryrun

import (
	stded25519 "crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/islishude/tss"
)

type identitySigner struct {
	private stded25519.PrivateKey
}

// SignEnvelopeDigest signs one canonical envelope digest.
func (s identitySigner) SignEnvelopeDigest(digest [32]byte) ([]byte, error) {
	return stded25519.Sign(s.private, digest[:]), nil
}

// Security owns ephemeral authentication keys and routing helpers for one
// single-process protocol execution.
type Security struct {
	private          map[tss.PartyID]stded25519.PrivateKey
	public           map[tss.PartyID]stded25519.PublicKey
	ackVerifier      tss.BroadcastAckVerifier
	envelopeVerifier tss.EnvelopeSignatureVerifier
}

type envelopeVerifier struct {
	public map[tss.PartyID]stded25519.PublicKey
}

// VerifyEnvelopeSignature verifies an ephemeral party identity signature.
func (v envelopeVerifier) VerifyEnvelopeSignature(party tss.PartyID, digest [32]byte, signature []byte) error {
	publicKey, ok := v.public[party]
	if !ok {
		return fmt.Errorf("unknown envelope signer %d", party)
	}
	if !stded25519.Verify(publicKey, digest[:], signature) {
		return errors.New("invalid envelope signature")
	}
	return nil
}

// New creates fresh ephemeral authentication keys for parties.
func New(parties tss.PartySet, reader io.Reader) (*Security, error) {
	if reader == nil {
		reader = rand.Reader
	}
	privateKeys := make(map[tss.PartyID]stded25519.PrivateKey, len(parties))
	publicKeys := make(map[tss.PartyID]stded25519.PublicKey, len(parties))
	for _, party := range parties {
		publicKey, privateKey, err := stded25519.GenerateKey(reader)
		if err != nil {
			for _, key := range privateKeys {
				clear(key)
			}
			return nil, err
		}
		privateKeys[party] = privateKey
		publicKeys[party] = publicKey
	}
	ackVerifier := tss.NewInMemoryAckVerifier(func(party tss.PartyID, digest [32]byte, signature []byte) error {
		publicKey, ok := publicKeys[party]
		if !ok {
			return fmt.Errorf("unknown broadcast signer %d", party)
		}
		if !stded25519.Verify(publicKey, digest[:], signature) {
			return errors.New("invalid broadcast acknowledgment")
		}
		return nil
	})
	verifier := envelopeVerifier{public: publicKeys}
	return &Security{
		private:          privateKeys,
		public:           publicKeys,
		ackVerifier:      ackVerifier,
		envelopeVerifier: verifier,
	}, nil
}

// Destroy clears ephemeral private identity keys.
func (s *Security) Destroy() {
	if s == nil {
		return
	}
	for party, key := range s.private {
		clear(key)
		delete(s.private, party)
	}
}

// Signer returns the envelope signer bound to party.
func (s *Security) Signer(party tss.PartyID) (tss.EnvelopeSigner, error) {
	privateKey, ok := s.private[party]
	if !ok {
		return nil, fmt.Errorf("missing identity key for party %d", party)
	}
	return identitySigner{private: privateKey}, nil
}

// Guard builds a production guard backed by the ephemeral identity set.
func (s *Security) Guard(self tss.PartyID, parties tss.PartySet, protocol tss.ProtocolID, sessionID tss.SessionID, policies tss.PolicySet) (*tss.EnvelopeGuard, error) {
	return (tss.GuardConfig{
		Self: self, Parties: parties, Protocol: protocol, SessionID: sessionID,
		Policies: policies, Cache: tss.NewInMemoryReplayCache(),
		AckVerifier: s.ackVerifier, EnvelopeVerifier: s.envelopeVerifier,
	}).BuildGuard()
}

// Route drains queue through authenticated, policy-aware in-memory delivery.
func (s *Security) Route(queue []tss.Envelope, recipients tss.PartySet, policies tss.PolicySet, handle func(tss.PartyID, tss.InboundEnvelope) ([]tss.Envelope, error)) error {
	defer func() {
		clearEnvelopePayloads(queue)
	}()
	for len(queue) > 0 {
		env := queue[0]
		queue[0] = tss.Envelope{}
		queue = queue[1:]
		err := func() error {
			defer clear(env.Payload)
			inbound, err := s.open(env, recipients, policies)
			if err != nil {
				return err
			}
			for _, party := range recipients {
				if party == env.From || (env.To != tss.BroadcastPartyId && env.To != party) {
					continue
				}
				out, err := handle(party, inbound)
				if err != nil {
					clearEnvelopePayloads(out)
					return fmt.Errorf("deliver %s from %d to %d: %w", env.PayloadType, env.From, party, err)
				}
				queue = append(queue, out...)
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

func clearEnvelopePayloads(envelopes []tss.Envelope) {
	for i := range envelopes {
		clear(envelopes[i].Payload)
		envelopes[i].Payload = nil
	}
}

func (s *Security) open(env tss.Envelope, certificateParties tss.PartySet, policies tss.PolicySet) (tss.InboundEnvelope, error) {
	policy, err := policies.Match(env.Protocol, env.Round, env.PayloadType)
	if err != nil {
		return tss.InboundEnvelope{}, err
	}
	protection := tss.ChannelPlaintext
	if policy.Confidentiality == tss.ConfidentialityRequired {
		protection = tss.ChannelConfidential
	}
	var certificate *tss.BroadcastCertificate
	if policy.BroadcastConsistency == tss.BroadcastConsistencyRequired {
		acks := make([]tss.BroadcastAck, 0, len(certificateParties))
		for _, party := range certificateParties {
			privateKey, ok := s.private[party]
			if !ok {
				return tss.InboundEnvelope{}, fmt.Errorf("missing broadcast key for party %d", party)
			}
			signer := tss.NewInMemoryAckSigner(party, func(digest [32]byte) ([]byte, error) {
				return stded25519.Sign(privateKey, digest[:]), nil
			})
			ack, err := tss.SignBroadcastAck(env, party, signer)
			if err != nil {
				return tss.InboundEnvelope{}, err
			}
			acks = append(acks, ack)
		}
		certificate, err = tss.NewBroadcastCertificate(env, certificateParties, acks)
		if err != nil {
			return tss.InboundEnvelope{}, err
		}
	}
	raw, err := env.MarshalBinary()
	if err != nil {
		return tss.InboundEnvelope{}, err
	}
	defer clear(raw)
	options := make([]tss.OpenOption, 0, 1)
	if certificate != nil {
		options = append(options, tss.WithBroadcastCertificate(certificate))
	}
	return tss.OpenEnvelope(raw, tss.ReceiveInfo{
		Peer: env.From, Protection: protection, ChannelID: "trusted-dealer-in-memory", PeerKeyID: fmt.Sprintf("party-%d", env.From),
	}, options...)
}
