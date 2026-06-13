//go:build integration

package secp256k1_test

import (
	stded25519 "crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/islishude/tss"
	cggmp "github.com/islishude/tss/cggmp21/secp256k1"
)

type exampleCGGMPSecurity struct {
	private  map[tss.PartyID]stded25519.PrivateKey
	verifier tss.BroadcastAckVerifier
}

func newExampleCGGMPSecurity(parties tss.PartySet) *exampleCGGMPSecurity {
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
	return &exampleCGGMPSecurity{
		private:  privateKeys,
		verifier: verifier,
	}
}

func (s *exampleCGGMPSecurity) guard(self tss.PartyID, parties tss.PartySet, sessionID tss.SessionID) (*tss.EnvelopeGuard, error) {
	return (tss.GuardConfig{
		Self:        self,
		Parties:     parties,
		Protocol:    tss.ProtocolCGGMP21Secp256k1,
		SessionID:   sessionID,
		Policies:    cggmp.CGGMP21Policies(),
		Cache:       tss.NewInMemoryReplayCache(),
		AckVerifier: s.verifier,
	}).BuildGuard()
}

func (s *exampleCGGMPSecurity) receive(env tss.Envelope, certificateParties tss.PartySet) (tss.Envelope, error) {
	policy, err := cggmp.CGGMP21Policies().Match(env.Protocol, env.Round, env.PayloadType)
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

func (s *exampleCGGMPSecurity) route(
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

func runExampleCGGMPKeygen(parties []tss.PartyID, threshold int, opts cggmp.KeygenOptions) (map[tss.PartyID]*cggmp.KeyShare, error) {
	partySet := tss.PartySet(parties)
	security := newExampleCGGMPSecurity(partySet)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		return nil, err
	}
	sessions := make(map[tss.PartyID]*cggmp.KeygenSession, len(parties))
	queue := make([]tss.Envelope, 0)
	for _, id := range parties {
		guard, err := security.guard(id, partySet, sessionID)
		if err != nil {
			return nil, err
		}
		session, out, err := cggmp.StartKeygenWithOptions(tss.ThresholdConfig{
			Threshold: threshold,
			Parties:   parties,
			Self:      id,
			SessionID: sessionID,
		}, opts, guard)
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

	shares := make(map[tss.PartyID]*cggmp.KeyShare, len(parties))
	for _, id := range parties {
		share, ok := sessions[id].KeyShare()
		if !ok {
			return nil, fmt.Errorf("keygen not complete for party %d", id)
		}
		shares[id] = share
	}
	return shares, nil
}

func runExampleCGGMPPresign(
	shares map[tss.PartyID]*cggmp.KeyShare,
	signers []tss.PartyID,
	ctx cggmp.PresignContext,
) (map[tss.PartyID]*cggmp.Presign, error) {
	signerSet := tss.PartySet(signers)
	security := newExampleCGGMPSecurity(signerSet)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		return nil, err
	}
	sessions := make(map[tss.PartyID]*cggmp.PresignSession, len(signers))
	queue := make([]tss.Envelope, 0)
	for _, id := range signers {
		guard, err := security.guard(id, signerSet, sessionID)
		if err != nil {
			return nil, err
		}
		session, out, err := cggmp.StartPresignWithContext(shares[id], sessionID, signers, ctx, guard)
		if err != nil {
			return nil, err
		}
		sessions[id] = session
		queue = append(queue, out...)
	}
	if err := security.route(queue, signerSet, func(tss.Envelope) tss.PartySet {
		return signerSet
	}, func(id tss.PartyID, env tss.Envelope) ([]tss.Envelope, error) {
		return sessions[id].HandlePresignMessage(env)
	}); err != nil {
		return nil, err
	}

	presigns := make(map[tss.PartyID]*cggmp.Presign, len(signers))
	for _, id := range signers {
		presign, ok := sessions[id].Presign()
		if !ok {
			return nil, fmt.Errorf("presign not complete for party %d", id)
		}
		presigns[id] = presign
	}
	return presigns, nil
}

func runExampleCGGMPSign(
	shares map[tss.PartyID]*cggmp.KeyShare,
	presigns map[tss.PartyID]*cggmp.Presign,
	signers []tss.PartyID,
	request cggmp.SignRequest,
) ([]byte, *cggmp.Signature, error) {
	signerSet := tss.PartySet(signers)
	security := newExampleCGGMPSecurity(signerSet)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		return nil, nil, err
	}
	sessions := make(map[tss.PartyID]*cggmp.SignSession, len(signers))
	queue := make([]tss.Envelope, 0, len(signers))
	for _, id := range signers {
		guard, err := security.guard(id, signerSet, sessionID)
		if err != nil {
			return nil, nil, err
		}
		session, out, err := cggmp.StartSign(shares[id], presigns[id], sessionID, request, guard)
		if err != nil {
			return nil, nil, err
		}
		sessions[id] = session
		queue = append(queue, out...)
	}
	if err := security.route(queue, signerSet, func(tss.Envelope) tss.PartySet {
		return signerSet
	}, func(id tss.PartyID, env tss.Envelope) ([]tss.Envelope, error) {
		return sessions[id].HandleSignMessage(env)
	}); err != nil {
		return nil, nil, err
	}
	signature, ok := sessions[signers[0]].Signature()
	if !ok {
		return nil, nil, errors.New("signing not complete")
	}
	return shares[signers[0]].PublicKeyBytes(), signature, nil
}

type exampleFilePresignStore struct {
	directory string
}

func newExampleFilePresignStore() (*exampleFilePresignStore, func(), error) {
	directory, err := os.MkdirTemp("", "tss-presign-claims-")
	if err != nil {
		return nil, nil, err
	}
	return &exampleFilePresignStore{directory: directory}, func() {
		_ = os.RemoveAll(directory)
	}, nil
}

func (s *exampleFilePresignStore) ClaimPresign(presignID []byte) error {
	path := filepath.Join(s.directory, hex.EncodeToString(presignID))
	// The directory is caller-created and the filename is fixed-width hex, so
	// no untrusted path component can escape the claim directory.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec
	if errors.Is(err, os.ErrExist) {
		return cggmp.ErrPresignAlreadyConsumed
	}
	if err != nil {
		return err
	}
	return file.Close()
}

func examplePresignContext() cggmp.PresignContext {
	return cggmp.PresignContext{
		KeyID:         "example-key",
		ChainID:       "example-chain",
		PolicyDomain:  "example-policy",
		MessageDomain: "example-message",
	}
}

func mergeExampleCGGMPPartySets(sets ...[]tss.PartyID) tss.PartySet {
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
