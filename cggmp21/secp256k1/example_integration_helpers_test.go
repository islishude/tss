//go:build integration

package secp256k1_test

import (
	"bytes"
	"context"
	stded25519 "crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/islishude/tss"
	cggmp "github.com/islishude/tss/cggmp21/secp256k1"
	"github.com/islishude/tss/tssrun"
)

// The helpers in this file run multiple protocol parties in one Go process.
// They simulate a distributed deployment for executable examples only.
//
// In production, each party runs in its own process. A coordinator or proposer
// creates public run metadata containing one SessionID, party set, threshold,
// signer set, and context. Every party validates that metadata, reconstructs an
// equivalent local plan, starts its own local session, and routes envelopes over
// authenticated transport.
type exampleProtocolRun struct {
	runID     string
	protocol  tss.ProtocolID
	kind      string
	sessionID tss.SessionID
	parties   tss.PartySet
	signers   tss.PartySet
	threshold int
}

type exampleKeygenJob struct {
	run            exampleProtocolRun
	limits         *cggmp.Limits
	securityParams cggmp.SecurityParams
	planHash       []byte
}

type examplePresignJob struct {
	run     exampleProtocolRun
	context tss.SigningContext
}

type exampleSignJob struct {
	run     exampleProtocolRun
	request cggmp.SignRequest
	stores  map[tss.PartyID]tssrun.LifecycleStore
}

type exampleCGGMPSecurity struct {
	// private contains the example transport identities used to acknowledge
	// broadcasts. These keys authenticate transport metadata only; they are
	// independent from the threshold ECDSA shares produced by CGGMP21.
	private          map[tss.PartyID]stded25519.PrivateKey
	verifier         tss.BroadcastAckVerifier
	envelopeVerifier tss.EnvelopeSignatureVerifier
}

type exampleEnvelopeSigner struct{ private stded25519.PrivateKey }

func (s exampleEnvelopeSigner) SignEnvelopeDigest(digest [32]byte) ([]byte, error) {
	return stded25519.Sign(s.private, digest[:]), nil
}

type exampleEnvelopeVerifier struct {
	public map[tss.PartyID]stded25519.PublicKey
}

func (v exampleEnvelopeVerifier) VerifyEnvelopeSignature(party tss.PartyID, digest [32]byte, signature []byte) error {
	public, ok := v.public[party]
	if !ok || !stded25519.Verify(public, digest[:], signature) {
		return errors.New("invalid envelope sender signature")
	}
	return nil
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
		private:          privateKeys,
		verifier:         verifier,
		envelopeVerifier: exampleEnvelopeVerifier{public: publicKeys},
	}
}

func (s *exampleCGGMPSecurity) envelopeSigner(party tss.PartyID) (tss.EnvelopeSigner, error) {
	private, ok := s.private[party]
	if !ok {
		return nil, fmt.Errorf("missing envelope signer for party %d", party)
	}
	return exampleEnvelopeSigner{private: private}, nil
}

func exampleKeyShareMetadata(share *cggmp.KeyShare) cggmp.KeySharePublicMetadata {
	metadata, ok := share.PublicMetadata()
	if !ok {
		panic("missing CGGMP key-share metadata")
	}
	return metadata
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
		Self:             self,
		Parties:          parties,
		Protocol:         tss.ProtocolCGGMP21Secp256k1,
		SessionID:        sessionID,
		Policies:         cggmp.CGGMP21Policies(),
		Cache:            tss.NewInMemoryReplayCache(),
		AckVerifier:      s.verifier,
		EnvelopeVerifier: s.envelopeVerifier,
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

func newExampleCGGMPKeygenJob(option cggmp.KeygenPlanOption) (exampleKeygenJob, error) {
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		return exampleKeygenJob{}, err
	}
	option.SessionID = sessionID
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
		return exampleKeygenJob{}, err
	}
	planHash, err := plan.Digest()
	if err != nil {
		return exampleKeygenJob{}, err
	}
	snapshot, ok := plan.Snapshot()
	if !ok {
		return exampleKeygenJob{}, errors.New("missing example keygen plan snapshot")
	}
	return exampleKeygenJob{
		run: exampleProtocolRun{
			runID:     "example-cggmp-keygen",
			protocol:  tss.ProtocolCGGMP21Secp256k1,
			kind:      "keygen",
			sessionID: snapshot.SessionID,
			parties:   snapshot.Parties,
			threshold: snapshot.Threshold,
		},
		limits:         option.Limits,
		securityParams: snapshot.SecurityParams,
		planHash:       append([]byte(nil), planHash...),
	}, nil
}

func startExampleCGGMPKeygenParty(job exampleKeygenJob, self tss.PartyID, security *exampleCGGMPSecurity) (*cggmp.KeygenSession, []tss.Envelope, error) {
	securityParams := job.securityParams
	plan, err := cggmp.NewKeygenPlan(cggmp.KeygenPlanOption{
		SessionID:      job.run.sessionID,
		Parties:        job.run.parties,
		Threshold:      job.run.threshold,
		Limits:         job.limits,
		SecurityParams: &securityParams,
	})
	if err != nil {
		return nil, nil, err
	}
	planHash, err := plan.Digest()
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(planHash, job.planHash) {
		return nil, nil, errors.New("example keygen plan hash mismatch")
	}
	guard, err := security.guard(self, job.run.parties, job.run.sessionID)
	if err != nil {
		return nil, nil, err
	}
	signer, err := security.envelopeSigner(self)
	if err != nil {
		return nil, nil, err
	}
	return cggmp.StartKeygen(plan, tss.LocalConfig{Self: self, EnvelopeSigner: signer}, guard)
}

// runExampleCGGMPKeygen executes a complete dealerless key-generation lifecycle
// using only the package's public integration API. This is a single-process
// simulator: it creates one keygen job, then starts each party as if that party
// had reconstructed the plan locally from accepted run metadata.
func runExampleCGGMPKeygen(option cggmp.KeygenPlanOption) (map[tss.PartyID]*cggmp.KeyShare, error) {
	job, err := newExampleCGGMPKeygenJob(option)
	if err != nil {
		return nil, err
	}
	parties := job.run.parties
	security := newExampleCGGMPSecurity(parties)
	sessions := make(map[tss.PartyID]*cggmp.KeygenSession, len(parties))
	queue := make([]tss.Envelope, 0)
	for _, id := range parties {
		session, out, err := startExampleCGGMPKeygenParty(job, id, security)
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
		return sessions[id].Handle(env)
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

func newExampleCGGMPPresignJob(signers tss.PartySet, ctx tss.SigningContext) (examplePresignJob, error) {
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		return examplePresignJob{}, err
	}
	return examplePresignJob{
		run: exampleProtocolRun{
			runID:     "example-cggmp-presign",
			protocol:  tss.ProtocolCGGMP21Secp256k1,
			kind:      "presign",
			sessionID: sessionID,
			parties:   signers.Clone(),
			signers:   signers.Clone(),
			threshold: len(signers),
		},
		context: ctx.Clone(),
	}, nil
}

func startExampleCGGMPPresignParty(job examplePresignJob, share *cggmp.KeyShare, store tssrun.LifecycleStore, security *exampleCGGMPSecurity) (*cggmp.PresignSession, []tss.Envelope, error) {
	if share == nil {
		return nil, nil, errors.New("missing example key share")
	}
	if store == nil {
		return nil, nil, errors.New("missing example lifecycle store")
	}
	self := share.PartyID()
	guard, err := security.guard(self, job.run.signers, job.run.sessionID)
	if err != nil {
		return nil, nil, err
	}
	plan, err := cggmp.NewPresignPlan(cggmp.PresignPlanOption{
		Key:       share,
		SessionID: job.run.sessionID,
		PresignID: job.run.sessionID[:],
		Signers:   job.run.signers,
		Context:   job.context,
	})
	if err != nil {
		return nil, nil, err
	}
	signer, err := security.envelopeSigner(self)
	if err != nil {
		return nil, nil, err
	}
	binding, err := installExampleGeneration(store, share, job.context.KeyID)
	if err != nil {
		return nil, nil, err
	}
	return cggmp.StartPresign(plan, cggmp.PresignRuntime{
		Local: tss.LocalConfig{Self: self, EnvelopeSigner: signer}, Guard: guard,
		LifecycleStore: store, Binding: binding,
	})
}

// runExampleCGGMPPresign performs the offline phase for the selected signer set.
// Secret presign material is installed atomically in stores; the returned
// descriptors contain only public metadata and canonical store slots.
func runExampleCGGMPPresign(
	shares map[tss.PartyID]*cggmp.KeyShare,
	signers tss.PartySet,
	ctx tss.SigningContext,
	stores map[tss.PartyID]tssrun.LifecycleStore,
) (map[tss.PartyID]cggmp.PersistedPresign, error) {
	job, err := newExampleCGGMPPresignJob(signers, ctx)
	if err != nil {
		return nil, err
	}
	signerSet := job.run.signers
	security := newExampleCGGMPSecurity(signerSet)
	sessions := make(map[tss.PartyID]*cggmp.PresignSession, len(signers))
	queue := make([]tss.Envelope, 0)
	for _, id := range signers {
		session, out, err := startExampleCGGMPPresignParty(job, shares[id], stores[id], security)
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
		return sessions[id].Handle(env)
	}); err != nil {
		return nil, err
	}

	presigns := make(map[tss.PartyID]cggmp.PersistedPresign, len(signers))
	for _, id := range signers {
		presign, ok := sessions[id].Presign()
		if !ok {
			return nil, fmt.Errorf("presign not complete for party %d", id)
		}
		presigns[id] = presign
		sessions[id].Destroy()
	}
	return presigns, nil
}

func newExampleCGGMPSignJob(signers tss.PartySet, request cggmp.SignRequest, stores map[tss.PartyID]tssrun.LifecycleStore) (exampleSignJob, error) {
	// The signing session ID is generated for this online signing attempt.
	// It is distinct from the earlier presign session ID.
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		return exampleSignJob{}, err
	}
	for _, signer := range signers {
		if stores[signer] == nil {
			return exampleSignJob{}, fmt.Errorf("missing example lifecycle store for party %d", signer)
		}
	}
	return exampleSignJob{
		run: exampleProtocolRun{
			runID:     "example-cggmp-sign",
			protocol:  tss.ProtocolCGGMP21Secp256k1,
			kind:      "sign",
			sessionID: sessionID,
			parties:   signers.Clone(),
			signers:   signers.Clone(),
			threshold: len(signers),
		},
		request: request.Clone(),
		stores:  stores,
	}, nil
}

func startExampleCGGMPSignParty(job exampleSignJob, share *cggmp.KeyShare, presign cggmp.PersistedPresign, security *exampleCGGMPSecurity) (*cggmp.SignSession, []tss.Envelope, error) {
	if share == nil {
		return nil, nil, errors.New("missing example key share")
	}
	if presign.SlotID() == "" {
		return nil, nil, errors.New("missing example presign")
	}
	self := share.PartyID()
	guard, err := security.guard(self, job.run.signers, job.run.sessionID)
	if err != nil {
		return nil, nil, err
	}
	metadata := presign.PublicMetadata()
	plan, err := cggmp.NewSignPlan(cggmp.SignPlanOption{
		Key:     share,
		Presign: metadata,
		Intent: cggmp.SignIntent{
			SessionID: job.run.sessionID,
			Context:   job.request.Context,
			Message:   job.request.Message,
			Signers:   job.run.signers,
		},
	})
	if err != nil {
		return nil, nil, err
	}
	signer, err := security.envelopeSigner(self)
	if err != nil {
		return nil, nil, err
	}
	runtime, err := prepareExampleSignRuntime(job, share, presign, signer, guard)
	if err != nil {
		return nil, nil, err
	}
	return cggmp.StartSign(plan, runtime)
}

func prepareExampleSignRuntime(job exampleSignJob, share *cggmp.KeyShare, presign cggmp.PersistedPresign, signer tss.EnvelopeSigner, guard *tss.EnvelopeGuard) (cggmp.SignRuntime, error) {
	self := share.PartyID()
	store := job.stores[self]
	binding, err := exampleGenerationBinding(share, job.request.Context.KeyID)
	if err != nil {
		return cggmp.SignRuntime{}, err
	}
	policy, err := cggmp.CGGMP21Policies().Match(tss.ProtocolCGGMP21Secp256k1, 1, tss.PayloadType("cggmp21.secp256k1.sign.partial"))
	if err != nil {
		return cggmp.SignRuntime{}, err
	}
	return cggmp.SignRuntime{
		Local:          tss.LocalConfig{Self: self, EnvelopeSigner: signer},
		Guard:          guard,
		LifecycleStore: store,
		Binding:        binding,
		PresignID:      presign.SlotID(),
		AttemptID:      fmt.Sprintf("example-sign-%d-%x", self, job.run.sessionID),
		DeliveryPolicy: cggmp.SignAttemptDeliveryPolicy{
			Mode:                 policy.Mode,
			Confidentiality:      policy.Confidentiality,
			BroadcastConsistency: policy.BroadcastConsistency,
			Recipients:           job.run.signers.Clone(),
		},
	}, nil
}

// runExampleCGGMPSign executes the online phase and returns the common group
// public key together with the threshold signature. StartSign performs the
// durable one-use claim through the configured presign store, so a
// successful or conflicting committed attempt cannot reuse these presigns.
func runExampleCGGMPSign(
	shares map[tss.PartyID]*cggmp.KeyShare,
	presigns map[tss.PartyID]cggmp.PersistedPresign,
	signers tss.PartySet,
	request cggmp.SignRequest,
	stores map[tss.PartyID]tssrun.LifecycleStore,
) ([]byte, *cggmp.Signature, error) {
	job, err := newExampleCGGMPSignJob(signers, request, stores)
	if err != nil {
		return nil, nil, err
	}
	signerSet := job.run.signers
	security := newExampleCGGMPSecurity(signerSet)
	sessions := make(map[tss.PartyID]*cggmp.SignSession, len(signers))
	queue := make([]tss.Envelope, 0, len(signers))
	for _, id := range signers {
		session, out, err := startExampleCGGMPSignParty(job, shares[id], presigns[id], security)
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
		return sessions[id].Handle(env)
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
	// material is exposed by PublicMetadata.
	return exampleKeyShareMetadata(shares[signers[0]]).PublicKey, signature, nil
}

func exampleGenerationBinding(share *cggmp.KeyShare, keyID string) (tssrun.GenerationBinding, error) {
	keyMetadata, ok := share.PublicMetadata()
	if !ok || keyMetadata.Epoch == nil {
		return tssrun.GenerationBinding{}, errors.New("invalid public key-share metadata")
	}
	epochID, err := tssrun.NewEpochID(keyMetadata.Epoch.EpochID)
	if err != nil {
		return tssrun.GenerationBinding{}, err
	}
	return tssrun.GenerationBinding{
		KeyID: keyID, KeyGeneration: tssrun.KeyGeneration(fmt.Sprintf("keygen-%x", keyMetadata.KeygenTranscriptHash)), EpochID: epochID,
	}, nil
}

func installExampleGeneration(store tssrun.LifecycleStore, share *cggmp.KeyShare, keyID string) (tssrun.GenerationBinding, error) {
	binding, err := exampleGenerationBinding(share, keyID)
	if err != nil {
		return tssrun.GenerationBinding{}, err
	}
	metadata, _ := share.PublicMetadata()
	blob, err := share.MarshalBinary()
	if err != nil {
		return tssrun.GenerationBinding{}, err
	}
	defer clear(blob)
	if _, err := store.InstallInitialGeneration(context.Background(), binding, blob, metadata.PlanHash); err != nil {
		return tssrun.GenerationBinding{}, err
	}
	return binding, nil
}

func newExampleFileLifecycleStores(parties tss.PartySet) (map[tss.PartyID]tssrun.LifecycleStore, func(), error) {
	directory, err := os.MkdirTemp("", "tss-lifecycle-")
	if err != nil {
		return nil, nil, err
	}
	stores := make(map[tss.PartyID]tssrun.LifecycleStore, len(parties))
	owned := make([]*tssrun.FileLifecycleStore, 0, len(parties))
	for _, party := range parties {
		store, openErr := tssrun.NewFileLifecycleStore(filepath.Join(directory, fmt.Sprintf("party-%d", party)), []byte("integration-example-passphrase"), &tss.PassphraseParams{
			Time:    1,
			Memory:  1024,
			Threads: 1,
		})
		if openErr != nil {
			for _, opened := range owned {
				_ = opened.Close()
			}
			_ = os.RemoveAll(directory)
			return nil, nil, openErr
		}
		stores[party] = store
		owned = append(owned, store)
	}
	return stores, func() {
		for _, store := range owned {
			_ = store.Close()
		}
		_ = os.RemoveAll(directory)
	}, nil
}

func examplePresignContext() tss.SigningContext {
	return tss.SigningContext{
		KeyID:         "example-key",
		ChainID:       "example-chain",
		Derivation:    tss.DerivationRequest{Scheme: tss.DerivationSchemeBIP32Secp256k1},
		PolicyDomain:  "example-policy",
		MessageDomain: "example-message",
	}
}
