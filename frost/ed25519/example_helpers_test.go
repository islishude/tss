package ed25519_test

import (
	stded25519 "crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/islishude/tss"
	frost "github.com/islishude/tss/frost/ed25519"
)

type exampleFROSTSecurity struct {
	private  map[tss.PartyID]stded25519.PrivateKey
	verifier tss.BroadcastAckVerifier
}

func newExampleFROSTSecurity(parties tss.PartySet) *exampleFROSTSecurity {
	privateKeys := make(map[tss.PartyID]stded25519.PrivateKey, len(parties))
	publicKeys := make(map[tss.PartyID]stded25519.PublicKey, len(parties))
	for _, id := range parties {
		var seed [stded25519.SeedSize]byte
		binary.BigEndian.PutUint32(seed[len(seed)-4:], uint32(id))
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

func (s *exampleFROSTSecurity) receive(env tss.Envelope, certificateParties tss.PartySet) (tss.Envelope, error) {
	policy, err := frost.FROSTPolicies().Match(env.Protocol, env.Round, env.PayloadType)
	if err != nil {
		return tss.Envelope{}, err
	}
	received := env.Clone()
	received.Security = tss.SecurityContext{
		Authenticated:      true,
		AuthenticatedParty: env.From,
		Confidential:       policy.Confidentiality == tss.ConfidentialityRequired,
		ChannelID:          "example-mtls",
		PeerKeyID:          fmt.Sprintf("party-%d", env.From),
	}
	if policy.BroadcastConsistency != tss.BroadcastConsistencyRequired {
		return received, nil
	}

	acks := make([]tss.BroadcastAck, 0, len(certificateParties))
	for _, id := range certificateParties {
		privateKey, ok := s.private[id]
		if !ok {
			return tss.Envelope{}, fmt.Errorf("missing broadcast key for party %d", id)
		}
		signer := tss.NewInMemoryAckSigner(id, func(digest [32]byte) ([]byte, error) {
			return stded25519.Sign(privateKey, digest[:]), nil
		})
		ack, err := tss.SignBroadcastAck(env, id, signer)
		if err != nil {
			return tss.Envelope{}, err
		}
		acks = append(acks, ack)
	}
	certificate, err := tss.NewBroadcastCertificate(env, certificateParties, acks)
	if err != nil {
		return tss.Envelope{}, err
	}
	received.Broadcast = certificate
	return received, nil
}

func (s *exampleFROSTSecurity) route(
	queue []tss.Envelope,
	recipients tss.PartySet,
	certificateParties func(tss.Envelope) tss.PartySet,
	handle func(tss.PartyID, tss.Envelope) ([]tss.Envelope, error),
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
			out, err := handle(id, received.Clone())
			if err != nil {
				return fmt.Errorf("deliver %s from %d to %d: %w", env.PayloadType, env.From, id, err)
			}
			queue = append(queue, out...)
		}
	}
	return nil
}

func runExampleFROSTKeygen(parties []tss.PartyID, threshold int, opts frost.KeygenOptions) (map[tss.PartyID]*frost.KeyShare, error) {
	partySet := tss.PartySet(parties)
	security := newExampleFROSTSecurity(partySet)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		return nil, err
	}
	sessions := make(map[tss.PartyID]*frost.KeygenSession, len(parties))
	queue := make([]tss.Envelope, 0)
	plan, err := frost.NewKeygenPlan(sessionID, parties, threshold, opts.EnableHD)
	if err != nil {
		return nil, err
	}
	for _, id := range parties {
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
	}, func(id tss.PartyID, env tss.Envelope) ([]tss.Envelope, error) {
		return sessions[id].HandleKeygenMessage(env)
	}); err != nil {
		return nil, err
	}

	shares := make(map[tss.PartyID]*frost.KeyShare, len(parties))
	for _, id := range parties {
		share, ok := sessions[id].KeyShare()
		if !ok {
			return nil, fmt.Errorf("keygen not complete for party %d", id)
		}
		shares[id] = share
	}
	return shares, nil
}

func runExampleFROSTSign(shares map[tss.PartyID]*frost.KeyShare, signers []tss.PartyID, message []byte, opts frost.SignOptions) ([]byte, []byte, error) {
	if len(signers) == 0 {
		return nil, nil, errors.New("no signers")
	}
	partySet := tss.PartySet(shares[signers[0]].Parties())
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
		plan, err := frost.NewSignPlan(shares[id], sessionID, signers, message, opts.AdditiveShift)
		if err != nil {
			return nil, nil, err
		}
		session, out, err := frost.StartSign(shares[id], plan, tss.LocalConfig{Self: id, Rand: opts.NonceReader}, guard)
		if err != nil {
			return nil, nil, err
		}
		sessions[id] = session
		queue = append(queue, out...)
	}
	if err := security.route(queue, tss.PartySet(signers), func(tss.Envelope) tss.PartySet {
		return partySet
	}, func(id tss.PartyID, env tss.Envelope) ([]tss.Envelope, error) {
		return sessions[id].HandleSignMessage(env)
	}); err != nil {
		return nil, nil, err
	}
	signature, ok := sessions[signers[0]].Signature()
	if !ok {
		return nil, nil, errors.New("signing not complete")
	}
	return sessions[signers[0]].VerifyKey(), signature, nil
}

func mergeExamplePartySets(sets ...[]tss.PartyID) tss.PartySet {
	seen := make(map[tss.PartyID]struct{})
	var merged []tss.PartyID
	for _, set := range sets {
		for _, id := range set {
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			merged = append(merged, id)
		}
	}
	return tss.PartySet(tss.SortParties(merged))
}
