//go:build integration

package secp256k1_test

import (
	stded25519 "crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"os"

	"github.com/islishude/tss"
	cggmp "github.com/islishude/tss/cggmp21/secp256k1"
)

type exampleCGGMPSecurity struct {
	// private contains the example transport identities used to acknowledge
	// broadcasts. These keys authenticate transport metadata only; they are
	// independent from the threshold ECDSA shares produced by CGGMP21.
	private  map[tss.PartyID]stded25519.PrivateKey
	verifier tss.BroadcastAckVerifier
}

// newExampleCGGMPSecurity builds a deterministic transport-security fixture for
// the example parties. A real integration must load independently provisioned
// transport identities instead of deriving private keys from public party IDs.
//
// Deterministic keys are acceptable here because this integration-tagged file is
// executable documentation: reproducibility matters, and none of these keys are
// used as protocol witnesses or persisted outside the process.
func newExampleCGGMPSecurity(parties tss.PartySet) *exampleCGGMPSecurity {
	privateKeys := make(map[tss.PartyID]stded25519.PrivateKey, len(parties))
	publicKeys := make(map[tss.PartyID]stded25519.PublicKey, len(parties))
	for _, id := range parties {
		// Place the party ID at the end of a fixed-size seed so every example
		// party receives a stable and distinct Ed25519 transport identity.
		var seed [stded25519.SeedSize]byte
		binary.BigEndian.PutUint32(seed[len(seed)-4:], id)
		privateKey := stded25519.NewKeyFromSeed(seed[:])
		privateKeys[id] = privateKey
		publicKeys[id] = privateKey.Public().(stded25519.PublicKey)
	}
	// The guard invokes this verifier for every acknowledgment attached to a
	// broadcast certificate. Verification is bound to both the claimed party
	// and the canonical digest computed by the tss package.
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

// guard constructs the receiving boundary for one local party. The guard checks
// protocol/session identity, sender and recipient rules, replay state,
// confidentiality metadata, and broadcast certificates before a message reaches
// a CGGMP21 state machine.
//
// Each party gets a separate replay cache because replay state belongs to the
// local receiver. The acknowledgment verifier is shared because all parties use
// the same example transport trust registry.
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

// receive adapts a protocol-produced envelope into an authenticated inbound
// envelope. Protocol sessions intentionally do not invent authentication,
// confidentiality, or broadcast-consistency claims; those properties must come
// from the caller's transport integration.
func (s *exampleCGGMPSecurity) receive(env tss.Envelope, certificateParties tss.PartySet) (tss.InboundEnvelope, error) {
	// Consult the same public policy table used by EnvelopeGuard so the
	// simulated transport marks confidentiality and broadcast requirements
	// consistently with the protocol round and payload type.
	policy, err := cggmp.CGGMP21Policies().Match(env.Protocol, env.Round, env.PayloadType)
	if err != nil {
		return tss.InboundEnvelope{}, err
	}
	protection := tss.ChannelPlaintext
	if policy.Confidentiality == tss.ConfidentialityRequired {
		protection = tss.ChannelConfidential
	}
	var certificate *tss.BroadcastCertificate
	open := func() (tss.InboundEnvelope, error) {
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
	if policy.BroadcastConsistency != tss.BroadcastConsistencyRequired {
		return open()
	}

	// Broadcast rounds require evidence that every expected participant saw
	// the same canonical envelope. The caller selects certificateParties
	// because the relevant set is lifecycle-specific (committee or signers).
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
	// NewBroadcastCertificate validates membership, acknowledgment uniqueness,
	// and signatures before the certificate is attached for guard validation.
	certificate, err = tss.NewBroadcastCertificate(env, certificateParties, acks)
	if err != nil {
		return tss.InboundEnvelope{}, err
	}
	return open()
}

// route drains all protocol output and delivers each envelope to its intended
// recipients until no state machine emits more work. It models a reliable,
// in-order example network; production transports may schedule messages
// differently, but must preserve the same authentication and policy metadata.
//
// certificateParties identifies the parties whose acknowledgments are required
// for each broadcast. handle dispatches to the recipient's lifecycle-specific
// state machine and returns any envelopes emitted by that state transition.
func (s *exampleCGGMPSecurity) route(
	queue []tss.Envelope,
	recipients tss.PartySet,
	certificateParties func(tss.Envelope) tss.PartySet,
	handle func(tss.PartyID, tss.InboundEnvelope) ([]tss.Envelope, error),
) error {
	for len(queue) > 0 {
		// Pop one envelope before handling it so newly emitted messages are
		// appended after work already queued by other parties.
		env := queue[0]
		queue = queue[1:]
		received, err := s.receive(env, certificateParties(env))
		if err != nil {
			return err
		}
		for _, id := range recipients {
			// A sender never receives its own output. Direct envelopes are
			// delivered only to Envelope.To; broadcasts have To == 0 and are
			// delivered to every other party in the active set.
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

// runExampleCGGMPKeygen executes a complete dealerless key-generation lifecycle
// using only the package's public integration API. All parties share one global
// plan, while each party owns an independent guard and KeygenSession.
func runExampleCGGMPKeygen(parties []tss.PartyID, threshold int, option cggmp.KeygenPlanOption) (map[tss.PartyID]*cggmp.KeyShare, error) {
	security := newExampleCGGMPSecurity(parties)
	// A fresh session ID prevents messages from another keygen execution from
	// being accepted by these guards or bound into this lifecycle transcript.
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		return nil, err
	}
	sessions := make(map[tss.PartyID]*cggmp.KeygenSession, len(parties))
	queue := make([]tss.Envelope, 0)
	// Construct the plan once so threshold, committee, HD policy, and Paillier
	// parameters are identical and transcript-bound for every participant.
	option.SessionID = sessionID
	option.Parties = parties
	option.Threshold = threshold
	if option.SecurityParams == nil {
		params := cggmp.SecurityParams{
			Ell:             256,
			EllPrime:        512,
			Epsilon:         64,
			ChallengeBits:   128,
			MinPaillierBits: 768,
		}
		option.SecurityParams = &params
	}
	plan, err := cggmp.NewKeygenPlan(option)
	if err != nil {
		return nil, err
	}
	for _, id := range parties {
		guard, err := security.guard(id, parties, sessionID)
		if err != nil {
			return nil, err
		}
		session, out, err := cggmp.StartKeygen(plan, tss.LocalConfig{Self: id}, guard)
		if err != nil {
			return nil, err
		}
		sessions[id] = session
		queue = append(queue, out...)
	}
	// Keygen broadcasts are certified by the complete keygen committee.
	if err := security.route(queue, parties, func(tss.Envelope) tss.PartySet {
		return parties
	}, func(id tss.PartyID, env tss.InboundEnvelope) ([]tss.Envelope, error) {
		return sessions[id].HandleKeygenMessage(env)
	}); err != nil {
		return nil, err
	}

	shares := make(map[tss.PartyID]*cggmp.KeyShare, len(parties))
	for _, id := range parties {
		// KeyShare succeeds only after that party's state machine has completed
		// every keygen round and validated all required peer contributions.
		share, ok := sessions[id].KeyShare()
		if !ok {
			return nil, fmt.Errorf("keygen not complete for party %d", id)
		}
		shares[id] = share
	}
	return shares, nil
}

// runExampleCGGMPPresign performs the offline phase for the selected signer set.
// The resulting presigns contain one-use secret material and must remain paired
// with the corresponding key share and signer identity.
func runExampleCGGMPPresign(
	shares map[tss.PartyID]*cggmp.KeyShare,
	signers []tss.PartyID,
	ctx cggmp.PresignContext,
) (map[tss.PartyID]*cggmp.Presign, error) {
	signerSet := tss.PartySet(signers)
	security := newExampleCGGMPSecurity(signerSet)
	// Presign is a separate protocol lifecycle, so it receives a session ID
	// distinct from keygen and from the later online-signing session.
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
		// NewPresignPlan binds the key, exact signer set, session, and caller
		// context before any presign messages are exchanged.
		plan, err := cggmp.NewPresignPlan(cggmp.PresignPlanOption{Key: shares[id], SessionID: sessionID, Signers: signers, Context: ctx})
		if err != nil {
			return nil, err
		}
		session, out, err := cggmp.StartPresign(shares[id], plan, tss.LocalConfig{Self: id}, guard)
		if err != nil {
			return nil, err
		}
		sessions[id] = session
		queue = append(queue, out...)
	}
	// Only selected signers participate, so they also form the acknowledgment
	// set for broadcasts emitted during this lifecycle.
	if err := security.route(queue, signerSet, func(tss.Envelope) tss.PartySet {
		return signerSet
	}, func(id tss.PartyID, env tss.InboundEnvelope) ([]tss.Envelope, error) {
		return sessions[id].HandlePresignMessage(env)
	}); err != nil {
		return nil, err
	}

	presigns := make(map[tss.PartyID]*cggmp.Presign, len(signers))
	for _, id := range signers {
		// Presign transfers the completed party-local one-use object out of the
		// session. Callers must store it as sensitive state and never duplicate
		// it to create independent signing attempts.
		presign, ok := sessions[id].Presign()
		if !ok {
			return nil, fmt.Errorf("presign not complete for party %d", id)
		}
		presigns[id] = presign
	}
	return presigns, nil
}

// runExampleCGGMPSign executes the online phase and returns the common group
// public key together with the threshold signature. StartSign performs the
// durable one-use claim through the SignRequest's configured presign store, so a
// successful or conflicting committed attempt cannot reuse these presigns.
func runExampleCGGMPSign(
	shares map[tss.PartyID]*cggmp.KeyShare,
	presigns map[tss.PartyID]*cggmp.Presign,
	signers []tss.PartyID,
	request cggmp.SignRequest,
) ([]byte, *cggmp.Signature, error) {
	signerSet := tss.PartySet(signers)
	security := newExampleCGGMPSecurity(signerSet)
	// The online phase has its own session identity even though it consumes
	// state created by the presign lifecycle.
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
		// Every signer builds the same logical plan from its matching share and
		// presign. The plan binds the digest and all request context before any
		// partial signature can be emitted.
		plan, err := cggmp.NewSignPlan(cggmp.SignPlanOption{Key: shares[id], Presign: presigns[id], SessionID: sessionID, Request: request})
		if err != nil {
			return nil, nil, err
		}
		session, out, err := cggmp.StartSign(shares[id], presigns[id], plan, tss.LocalConfig{Self: id}, guard)
		if err != nil {
			return nil, nil, err
		}
		sessions[id] = session
		queue = append(queue, out...)
	}
	// As in presign, the active signer set is both the delivery set and the
	// required acknowledgment set for broadcast-consistent rounds.
	if err := security.route(queue, signerSet, func(tss.Envelope) tss.PartySet {
		return signerSet
	}, func(id tss.PartyID, env tss.InboundEnvelope) ([]tss.Envelope, error) {
		return sessions[id].HandleSignMessage(env)
	}); err != nil {
		return nil, nil, err
	}
	// Every honest completed session derives the same final signature, so one
	// party's result is sufficient after all queued messages have been drained.
	signature, ok := sessions[signers[0]].Signature()
	if !ok {
		return nil, nil, errors.New("signing not complete")
	}
	// All key shares represent the same group public key; no private share
	// material is exposed by PublicKeyBytes.
	return shares[signers[0]].PublicKeyBytes(), signature, nil
}

func newExampleFileSignAttemptStore() (*cggmp.FileSignAttemptStore, func(), error) {
	directory, err := os.MkdirTemp("", "tss-sign-attempts-")
	if err != nil {
		return nil, nil, err
	}
	store, err := cggmp.NewFileSignAttemptStore(directory, []byte("integration-example-passphrase"), &tss.PassphraseParams{
		Time:    1,
		Memory:  1024,
		Threads: 1,
	})
	if err != nil {
		_ = os.RemoveAll(directory)
		return nil, nil, err
	}
	return store, func() {
		store.Destroy()
		_ = os.RemoveAll(directory)
	}, nil
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
