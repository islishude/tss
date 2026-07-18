package ed25519_test

import (
	stded25519 "crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/islishude/tss"
	frost "github.com/islishude/tss/frost/ed25519"
)

type exampleFROSTSignOptions struct {
	Context     tss.SigningContext
	NonceReader io.Reader
	Limits      *frost.Limits
}

type exampleFROSTSecurity struct {
	private  map[tss.PartyID]stded25519.PrivateKey
	verifier tss.BroadcastAckVerifier
}

func exampleFROSTSigningContext(paths ...[]uint32) tss.SigningContext {
	var path tss.DerivationPath
	if len(paths) > 0 {
		path = tss.DerivationPath(paths[0]).Clone()
	}
	return tss.SigningContext{
		KeyID:   "example-key",
		ChainID: "example-chain",
		Derivation: tss.DerivationRequest{
			Scheme: tss.DerivationSchemeEd25519KhovratovichLaw,
			Path:   path,
		},
		PolicyDomain:  "example-policy",
		MessageDomain: "example-message",
	}
}

func exampleFROSTKeyShareMetadata(key *frost.KeyShare) (frost.KeySharePublicMetadata, error) {
	metadata, ok := key.PublicMetadata()
	if !ok {
		return frost.KeySharePublicMetadata{}, errors.New("missing key-share metadata")
	}
	return metadata, nil
}

func newExampleFROSTSecurity(parties tss.PartySet) *exampleFROSTSecurity {
	privateKeys := make(map[tss.PartyID]stded25519.PrivateKey, len(parties))
	publicKeys := make(map[tss.PartyID]stded25519.PublicKey, len(parties))
	for _, id := range parties {
		var seed [stded25519.SeedSize]byte
		binary.BigEndian.PutUint32(seed[len(seed)-4:], id)
		privateKey := stded25519.NewKeyFromSeed(seed[:])
		privateKeys[id] = privateKey
		publicKeys[id] = privateKey.Public().(stded25519.PublicKey)
	}
	verifier := tss.NewInMemoryAckVerifier(func(party tss.PartyID, digest [32]byte, signature []byte) error {
		publicKey, ok := publicKeys[party]
		if !ok {
			return fmt.Errorf("unknown broadcast signer %d", party)
		}
		if !stded25519.Verify(publicKey, digest[:], signature) {
			return errors.New("invalid broadcast acknowledgment")
		}
		return nil
	})
	return &exampleFROSTSecurity{
		private:  privateKeys,
		verifier: verifier,
	}
}

func (s *exampleFROSTSecurity) guard(self tss.PartyID, parties tss.PartySet, sessionID tss.SessionID) (*tss.EnvelopeGuard, error) {
	return (tss.GuardConfig{
		Self:        self,
		Parties:     parties,
		Protocol:    tss.ProtocolFROSTEd25519,
		SessionID:   sessionID,
		Policies:    frost.FROSTPolicies(),
		Cache:       tss.NewInMemoryReplayCache(),
		AckVerifier: s.verifier,
	}).BuildGuard()
}

func (s *exampleFROSTSecurity) receive(env tss.Envelope, certificateParties tss.PartySet) (tss.InboundEnvelope, error) {
	policy, err := frost.FROSTPolicies().Match(env.Protocol, env.Round, env.PayloadType)
	if err != nil {
		return tss.InboundEnvelope{}, err
	}
	protection := tss.ChannelPlaintext
	if policy.Confidentiality == tss.ConfidentialityRequired {
		protection = tss.ChannelConfidential
	}
	var certificate *tss.BroadcastCertificate
	if policy.BroadcastConsistency != tss.BroadcastConsistencyRequired {
		raw, err := env.MarshalBinary()
		if err != nil {
			return tss.InboundEnvelope{}, err
		}
		return tss.OpenEnvelope(raw, tss.ReceiveInfo{
			Peer:       env.From,
			Protection: protection,
			ChannelID:  "example-mtls",
			PeerKeyID:  fmt.Sprintf("party-%d", env.From),
		})
	}

	acks := make([]tss.BroadcastAck, 0, len(certificateParties))
	for _, id := range certificateParties {
		privateKey, ok := s.private[id]
		if !ok {
			return tss.InboundEnvelope{}, fmt.Errorf("missing broadcast key for party %d", id)
		}
		signer := tss.NewInMemoryAckSigner(id, func(digest [32]byte) ([]byte, error) {
			return stded25519.Sign(privateKey, digest[:]), nil
		})
		ack, err := tss.SignBroadcastAck(env, id, signer)
		if err != nil {
			return tss.InboundEnvelope{}, err
		}
		acks = append(acks, ack)
	}
	certificate, err = tss.NewBroadcastCertificate(env, certificateParties, acks)
	if err != nil {
		return tss.InboundEnvelope{}, err
	}
	raw, err := env.MarshalBinary()
	if err != nil {
		return tss.InboundEnvelope{}, err
	}
	return tss.OpenEnvelope(raw, tss.ReceiveInfo{
		Peer:       env.From,
		Protection: protection,
		ChannelID:  "example-mtls",
		PeerKeyID:  fmt.Sprintf("party-%d", env.From),
	}, tss.WithBroadcastCertificate(certificate))
}

func (s *exampleFROSTSecurity) route(
	queue []tss.Envelope,
	recipients tss.PartySet,
	certificateParties func(tss.Envelope) tss.PartySet,
	handle func(tss.PartyID, tss.InboundEnvelope) ([]tss.Envelope, error),
) error {
	for len(queue) > 0 {
		env := queue[0]
		queue = queue[1:]
		received, err := s.receive(env, certificateParties(env))
		if err != nil {
			return err
		}
		for _, id := range recipients {
			if id == env.From || (env.To != 0 && env.To != id) {
				continue
			}
			out, err := handle(id, received)
			if err != nil {
				return fmt.Errorf("deliver %s from %d to %d: %w", env.PayloadType, env.From, id, err)
			}
			queue = append(queue, out...)
		}
	}
	return nil
}

func runExampleFROSTKeygen(option frost.KeygenPlanOption) (map[tss.PartyID]*frost.KeyShare, error) {
	partySet := option.Parties
	security := newExampleFROSTSecurity(partySet)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		return nil, err
	}
	option.SessionID = sessionID
	sessions := make(map[tss.PartyID]*frost.KeygenSession, len(partySet))
	queue := make([]tss.Envelope, 0)
	plan, err := frost.NewKeygenPlan(option)
	if err != nil {
		return nil, err
	}
	for _, id := range partySet {
		guard, err := security.guard(id, partySet, sessionID)
		if err != nil {
			return nil, err
		}
		session, out, err := frost.StartKeygen(plan, tss.LocalConfig{Self: id}, guard)
		if err != nil {
			return nil, err
		}
		sessions[id] = session
		queue = append(queue, out...)
	}
	if err := security.route(queue, partySet, func(tss.Envelope) tss.PartySet {
		return partySet
	}, func(id tss.PartyID, env tss.InboundEnvelope) ([]tss.Envelope, error) {
		return sessions[id].Handle(env)
	}); err != nil {
		return nil, err
	}

	shares := make(map[tss.PartyID]*frost.KeyShare, len(partySet))
	for _, id := range partySet {
		share, ok := sessions[id].KeyShare()
		if !ok {
			return nil, fmt.Errorf("keygen not complete for party %d", id)
		}
		shares[id] = share
	}
	return shares, nil
}

func runExampleFROSTSign(shares map[tss.PartyID]*frost.KeyShare, signers tss.PartySet, message []byte, opts exampleFROSTSignOptions) ([]byte, []byte, error) {
	if len(signers) == 0 {
		return nil, nil, errors.New("no signers")
	}
	metadata, err := exampleFROSTKeyShareMetadata(shares[signers[0]])
	if err != nil {
		return nil, nil, err
	}
	partySet := metadata.Parties
	security := newExampleFROSTSecurity(partySet)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		return nil, nil, err
	}
	sessions := make(map[tss.PartyID]*frost.SignSession, len(signers))
	queue := make([]tss.Envelope, 0, len(signers))
	for _, id := range signers {
		guard, err := security.guard(id, partySet, sessionID)
		if err != nil {
			return nil, nil, err
		}
		ctx := opts.Context
		if ctx.Derivation.Scheme == "" {
			ctx = exampleFROSTSigningContext()
		}
		plan, err := frost.NewSignPlan(frost.SignPlanOption{
			Key: shares[id],
			Intent: tss.SignIntent{
				SessionID: sessionID,
				Signers:   signers,
				Context:   ctx,
				Message:   message,
			},
			Limits: opts.Limits,
		})
		if err != nil {
			return nil, nil, err
		}
		session, out, err := frost.StartSign(shares[id], plan, frost.SignRuntime{
			Local: tss.LocalConfig{Self: id, Rand: opts.NonceReader},
			Guard: guard,
		})
		if err != nil {
			return nil, nil, err
		}
		sessions[id] = session
		queue = append(queue, out...)
	}
	if err := security.route(queue, signers, func(tss.Envelope) tss.PartySet {
		return signers
	}, func(id tss.PartyID, env tss.InboundEnvelope) ([]tss.Envelope, error) {
		return sessions[id].Handle(env)
	}); err != nil {
		return nil, nil, err
	}
	signature, ok := sessions[signers[0]].Signature()
	if !ok {
		return nil, nil, errors.New("signing not complete")
	}
	return sessions[signers[0]].VerificationKeyBytes(), signature, nil
}
