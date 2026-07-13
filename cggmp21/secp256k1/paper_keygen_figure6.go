package secp256k1

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/bip32util"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/zk/schnorr"
)

var (
	errFigure6MalformedPayload    = errors.New("malformed Figure 6 payload")
	errFigure6AttributableFailure = errors.New("attributable Figure 6 verification failure")
)

func figure6MalformedPayload(err error) error {
	return fmt.Errorf("%w: %w", errFigure6MalformedPayload, err)
}

func figure6AttributableFailure(err error) error {
	return fmt.Errorf("%w: %w", errFigure6AttributableFailure, err)
}

type figure6StartOption struct {
	Config            tss.ThresholdConfig
	Limits            Limits
	PlanHash          []byte
	Contribution      *secret.Scalar
	ChainContribution []byte
}

type figure6LocalState struct {
	contribution *secret.Scalar
	chainCode    []byte
	preparation  *schnorr.Preparation
	reveal       *figure6RevealPayload
}

func (s *figure6LocalState) destroy() {
	if s == nil {
		return
	}
	if s.contribution != nil {
		s.contribution.Destroy()
		s.contribution = nil
	}
	clear(s.chainCode)
	s.chainCode = nil
	if s.preparation != nil {
		s.preparation.Destroy()
		s.preparation = nil
	}
	if s.reveal != nil {
		clear(s.reveal.Rho)
		clear(s.reveal.Decommitment)
		s.reveal = nil
	}
}

type figure6PartySlot struct {
	commitment      []byte
	chainCodeCommit []byte
	reveal          *figure6RevealPayload
	proof           *figure6ProofPayload
}

type figure6Result struct {
	contribution *secret.Scalar
	publicKey    []byte
	rho          tss.SessionID
}

func (r *figure6Result) destroy() {
	if r == nil {
		return
	}
	if r.contribution != nil {
		r.contribution.Destroy()
		r.contribution = nil
	}
	r.publicKey = nil
}

type figure6State struct {
	cfg        tss.ThresholdConfig
	limits     Limits
	planHash   []byte
	local      *figure6LocalState
	slots      map[tss.PartyID]*figure6PartySlot
	revealSent bool
	proofSent  bool
	rho        tss.SessionID
	result     *figure6Result
	aborted    bool
}

func startFigure6(option figure6StartOption) (*figure6State, []tss.Envelope, error) {
	option.Config.Parties = option.Config.SortedParties()
	if err := option.Config.ValidateWithLimits(option.Limits.ThresholdLimits()); err != nil {
		return nil, nil, err
	}
	if len(option.PlanHash) != 32 {
		return nil, nil, errors.New("figure 6 plan hash must be 32 bytes")
	}
	state := &figure6State{
		cfg: option.Config, limits: option.Limits, planHash: bytes.Clone(option.PlanHash),
		slots: make(map[tss.PartyID]*figure6PartySlot, len(option.Config.Parties)),
	}
	for _, party := range option.Config.Parties {
		state.slots[party] = new(figure6PartySlot)
	}
	cleanup := true
	defer func() {
		if cleanup {
			state.destroy()
		}
	}()
	var contribution *secret.Scalar
	if option.Contribution != nil {
		contribution = option.Contribution.Clone()
	}
	if contribution == nil {
		scalar, err := secp.RandomScalar(option.Config.Reader())
		if err != nil {
			return nil, nil, err
		}
		contribution, err = secpSecretScalarFromScalar(scalar)
		if err != nil {
			return nil, nil, err
		}
	}
	publicScalar, err := secpScalarFromSecret(contribution)
	if err != nil {
		contribution.Destroy()
		return nil, nil, err
	}
	publicShare, err := secp.PointBytes(secp.ScalarBaseMult(publicScalar))
	if err != nil {
		contribution.Destroy()
		return nil, nil, err
	}
	preparation, err := schnorr.Prepare(option.Config.Reader(), publicShare)
	if err != nil {
		contribution.Destroy()
		return nil, nil, err
	}
	rho, err := sampleFigureCoin(option.Config.Reader())
	if err != nil {
		preparation.Destroy()
		contribution.Destroy()
		return nil, nil, err
	}
	decommitment, err := sampleFigureCoin(option.Config.Reader())
	if err != nil {
		preparation.Destroy()
		contribution.Destroy()
		clear(rho)
		return nil, nil, err
	}
	chainCode := bytes.Clone(option.ChainContribution)
	if chainCode == nil {
		chainCode, err = sampleFigureCoin(option.Config.Reader())
		if err != nil {
			preparation.Destroy()
			contribution.Destroy()
			clear(rho)
			clear(decommitment)
			return nil, nil, err
		}
	}
	if len(chainCode) != bip32util.ChainCodeSize {
		preparation.Destroy()
		contribution.Destroy()
		clear(rho)
		clear(decommitment)
		clear(chainCode)
		return nil, nil, errors.New("figure 6 chain-code contribution must be 32 bytes")
	}
	reveal := &figure6RevealPayload{
		Rho: rho, PublicShare: publicShare, SchnorrCommitment: preparation.Commitment(),
		Decommitment: decommitment, PlanHash: bytes.Clone(option.PlanHash),
	}
	commitment, err := figure6Commitment(option.Config.SessionID, option.Config.Self, rho, publicShare, reveal.SchnorrCommitment, decommitment, option.PlanHash)
	if err != nil {
		return nil, nil, err
	}
	chainCommitment := bip32util.ChainCodeCommitment(cggmpChainCodeCommitLabel, option.Config.SessionID, option.Config.Self, chainCode)
	state.local = &figure6LocalState{contribution: contribution, chainCode: chainCode, preparation: preparation, reveal: reveal}
	state.slots[option.Config.Self] = &figure6PartySlot{
		commitment: bytes.Clone(commitment), chainCodeCommit: bytes.Clone(chainCommitment), reveal: cloneFigure6Reveal(reveal),
	}
	payload, err := (figure6CommitmentPayload{Commitment: commitment, ChainCodeCommit: chainCommitment, PlanHash: option.PlanHash}).MarshalBinaryWithLimits(option.Limits)
	if err != nil {
		return nil, nil, err
	}
	env, err := newEnvelope(option.Config, keygenFigure6CommitmentRound, option.Config.Self, tss.BroadcastPartyId, payloadFigure6Commitment, payload)
	clear(payload)
	if err != nil {
		return nil, nil, err
	}
	if len(option.Config.Parties) == 1 {
		if err := state.completeSingleton(); err != nil {
			clear(env.Payload)
			return nil, nil, err
		}
	}
	cleanup = false
	return state, []tss.Envelope{env}, nil
}

// completeSingleton performs the vacuous local completion of Figure 6. The
// normal multi-party path is driven by the last remote reveal and proof, but a
// one-party test committee has no remote envelope that can trigger either
// transition. It still constructs and consumes the same Schnorr preparation
// and records the complete transcript before exposing the result.
func (s *figure6State) completeSingleton() error {
	if s == nil || len(s.cfg.Parties) != 1 || s.cfg.Parties[0] != s.cfg.Self || s.local == nil || s.local.reveal == nil {
		return errors.New("invalid singleton Figure 6 state")
	}
	contributions := map[tss.PartyID][]byte{s.cfg.Self: s.local.reveal.Rho}
	rho, err := xorFigureCoins(s.cfg.Parties, contributions, "rho")
	if err != nil {
		return err
	}
	domain, err := figure6SchnorrDomain(s.cfg.SessionID, rho, s.cfg.Self, s.planHash)
	if err != nil {
		return err
	}
	finalization, err := s.local.preparation.PrepareFinalize(domain, s.local.contribution)
	if err != nil {
		return err
	}
	defer finalization.Destroy()
	proof := finalization.Proof()
	if !bytes.Equal(proof.Commitment, s.local.reveal.SchnorrCommitment) {
		return errors.New("figure 6 finalization changed first message")
	}
	proofPayload := &figure6ProofPayload{Proof: proof, Rho: rho, PlanHash: bytes.Clone(s.planHash)}
	result := &figure6Result{
		contribution: s.local.contribution.Clone(),
		publicKey:    bytes.Clone(s.local.reveal.PublicShare),
		rho:          rho,
	}
	if err := finalization.Commit(); err != nil {
		clear(proofPayload.Proof.Commitment)
		clear(proofPayload.Proof.Response)
		proofPayload.Proof = nil
		clear(proofPayload.PlanHash)
		result.destroy()
		return err
	}
	s.slots[s.cfg.Self].proof = proofPayload
	s.revealSent = true
	s.proofSent = true
	s.rho = rho
	s.result = result
	return nil
}

func (s *figure6State) destroy() {
	if s == nil {
		return
	}
	s.aborted = true
	if s.local != nil {
		s.local.destroy()
		s.local = nil
	}
	if s.result != nil {
		s.result.destroy()
		s.result = nil
	}
	s.slots = nil
}

// releaseContribution destroys the Figure 6 witness after Figure 7 has taken
// its own copy. The public slots and the local chain-code opening remain until
// the post-keygen confirmation round has checked every commitment.
func (s *figure6State) releaseContribution() {
	if s == nil {
		return
	}
	if s.local != nil {
		if s.local.contribution != nil {
			s.local.contribution.Destroy()
			s.local.contribution = nil
		}
		if s.local.preparation != nil {
			s.local.preparation.Destroy()
			s.local.preparation = nil
		}
	}
	if s.result != nil && s.result.contribution != nil {
		s.result.contribution.Destroy()
		s.result.contribution = nil
	}
}

func (s *figure6State) completed() bool { return s != nil && !s.aborted && s.result != nil }

type preparedFigure6Inbound struct {
	out          []tss.Envelope
	result       *figure6Result
	commit       func() error
	finalization *schnorr.Finalization
	committed    bool
	cleanup      func()
}

func (p *preparedFigure6Inbound) destroy() {
	if p == nil || p.committed {
		return
	}
	if p.cleanup != nil {
		p.cleanup()
	}
	if p.finalization != nil {
		p.finalization.Destroy()
	}
	for i := range p.out {
		clear(p.out[i].Payload)
	}
}

func (p *preparedFigure6Inbound) apply() error {
	if p == nil || p.committed {
		return errors.New("invalid Figure 6 prepared transition")
	}
	if p.finalization != nil {
		if err := p.finalization.Commit(); err != nil {
			return err
		}
	}
	if p.commit != nil {
		if err := p.commit(); err != nil {
			return err
		}
	}
	p.committed = true
	return nil
}

func (s *figure6State) hasAccepted(env tss.Envelope) bool {
	slot := s.slots[env.From]
	if slot == nil {
		return false
	}
	switch env.PayloadType {
	case payloadFigure6Commitment:
		return slot.commitment != nil
	case payloadFigure6Reveal:
		return slot.reveal != nil
	case payloadFigure6Proof:
		return slot.proof != nil
	default:
		return false
	}
}

func (s *figure6State) prepareInbound(env tss.Envelope) (*preparedFigure6Inbound, error) {
	if s == nil || s.aborted || env.From == s.cfg.Self || !s.cfg.Parties.Contains(env.From) {
		return nil, errors.New("invalid Figure 6 inbound state or sender")
	}
	if s.hasAccepted(env) {
		return nil, tss.ErrDuplicateMessage
	}
	switch env.PayloadType {
	case payloadFigure6Commitment:
		return s.prepareCommitment(env)
	case payloadFigure6Reveal:
		return s.prepareReveal(env)
	case payloadFigure6Proof:
		return s.prepareProof(env)
	default:
		return nil, fmt.Errorf("unexpected Figure 6 payload %q", env.PayloadType)
	}
}

func (s *figure6State) prepareCommitment(env tss.Envelope) (*preparedFigure6Inbound, error) {
	if env.Round != keygenFigure6CommitmentRound || env.To != tss.BroadcastPartyId {
		return nil, errors.New("figure 6 commitment in wrong round or mode")
	}
	payload, err := tss.DecodeBinaryWithLimits[figure6CommitmentPayload](env.Payload, s.limits)
	if err != nil {
		return nil, figure6MalformedPayload(err)
	}
	if err := requirePlanHash("Figure 6 commitment", payload.PlanHash, s.planHash); err != nil {
		return nil, figure6AttributableFailure(err)
	}
	complete := true
	for _, party := range s.cfg.Parties {
		if party != env.From && s.slots[party].commitment == nil {
			complete = false
		}
	}
	prepared := &preparedFigure6Inbound{}
	if complete && !s.revealSent {
		encoded, err := s.local.reveal.MarshalBinaryWithLimits(s.limits)
		if err != nil {
			return nil, err
		}
		revealEnv, err := newEnvelope(s.cfg, keygenFigure6RevealRound, s.cfg.Self, tss.BroadcastPartyId, payloadFigure6Reveal, encoded)
		clear(encoded)
		if err != nil {
			return nil, err
		}
		prepared.out = []tss.Envelope{revealEnv}
	}
	prepared.commit = func() error {
		s.slots[env.From].commitment = bytes.Clone(payload.Commitment)
		s.slots[env.From].chainCodeCommit = bytes.Clone(payload.ChainCodeCommit)
		if complete {
			s.revealSent = true
		}
		return nil
	}
	return prepared, nil
}

func (s *figure6State) prepareReveal(env tss.Envelope) (*preparedFigure6Inbound, error) {
	if env.Round != keygenFigure6RevealRound || env.To != tss.BroadcastPartyId || s.slots[env.From].commitment == nil {
		return nil, errors.New("figure 6 reveal in wrong phase")
	}
	payload, err := tss.DecodeBinaryWithLimits[figure6RevealPayload](env.Payload, s.limits)
	if err != nil {
		return nil, figure6MalformedPayload(err)
	}
	if err := requirePlanHash("Figure 6 reveal", payload.PlanHash, s.planHash); err != nil {
		return nil, figure6AttributableFailure(err)
	}
	commitment, err := figure6Commitment(s.cfg.SessionID, env.From, payload.Rho, payload.PublicShare, payload.SchnorrCommitment, payload.Decommitment, s.planHash)
	if err != nil || !bytes.Equal(commitment, s.slots[env.From].commitment) {
		return nil, figure6AttributableFailure(errors.New("figure 6 reveal does not open commitment"))
	}
	contributions := make(map[tss.PartyID][]byte, len(s.cfg.Parties))
	complete := true
	for _, party := range s.cfg.Parties {
		if party == env.From {
			contributions[party] = payload.Rho
		} else if s.slots[party].reveal != nil {
			contributions[party] = s.slots[party].reveal.Rho
		} else {
			complete = false
		}
	}
	if !complete || s.proofSent {
		return &preparedFigure6Inbound{commit: func() error {
			s.slots[env.From].reveal = cloneFigure6Reveal(payload)
			return nil
		}}, nil
	}
	rho, err := xorFigureCoins(s.cfg.Parties, contributions, "rho")
	if err != nil {
		return nil, err
	}
	domain, err := figure6SchnorrDomain(s.cfg.SessionID, rho, s.cfg.Self, s.planHash)
	if err != nil {
		return nil, err
	}
	finalization, err := s.local.preparation.PrepareFinalize(domain, s.local.contribution)
	if err != nil {
		return nil, err
	}
	proof := finalization.Proof()
	if !bytes.Equal(proof.Commitment, s.local.reveal.SchnorrCommitment) {
		finalization.Destroy()
		return nil, errors.New("figure 6 finalization changed first message")
	}
	proofPayload := figure6ProofPayload{Proof: proof.Clone(), Rho: rho, PlanHash: s.planHash}
	encoded, err := proofPayload.MarshalBinaryWithLimits(s.limits)
	if err != nil {
		finalization.Destroy()
		return nil, err
	}
	proofEnv, err := newEnvelope(s.cfg, keygenFigure6ProofRound, s.cfg.Self, tss.BroadcastPartyId, payloadFigure6Proof, encoded)
	clear(encoded)
	if err != nil {
		finalization.Destroy()
		return nil, err
	}
	return &preparedFigure6Inbound{
		out: []tss.Envelope{proofEnv}, finalization: finalization,
		commit: func() error {
			s.slots[env.From].reveal = cloneFigure6Reveal(payload)
			s.slots[s.cfg.Self].proof = &proofPayload
			s.rho = rho
			s.proofSent = true
			return nil
		},
	}, nil
}

func (s *figure6State) prepareProof(env tss.Envelope) (*preparedFigure6Inbound, error) {
	if env.Round != keygenFigure6ProofRound || env.To != tss.BroadcastPartyId || !s.proofSent {
		return nil, errors.New("figure 6 proof in wrong phase")
	}
	payload, err := tss.DecodeBinaryWithLimits[figure6ProofPayload](env.Payload, s.limits)
	if err != nil {
		return nil, figure6MalformedPayload(err)
	}
	if err := requirePlanHash("Figure 6 proof", payload.PlanHash, s.planHash); err != nil {
		return nil, figure6AttributableFailure(err)
	}
	if payload.Rho != s.rho {
		return nil, figure6AttributableFailure(errors.New("figure 6 proof binding mismatch"))
	}
	reveal := s.slots[env.From].reveal
	if reveal == nil || !bytes.Equal(payload.Proof.Commitment, reveal.SchnorrCommitment) {
		return nil, figure6AttributableFailure(errors.New("figure 6 Schnorr first message mismatch"))
	}
	domain, err := figure6SchnorrDomain(s.cfg.SessionID, s.rho, env.From, s.planHash)
	if err != nil {
		return nil, err
	}
	if !schnorr.Verify(domain, reveal.PublicShare, payload.Proof) {
		return nil, figure6AttributableFailure(errors.New("invalid Figure 6 Schnorr proof"))
	}
	complete := true
	for _, party := range s.cfg.Parties {
		if party != env.From && s.slots[party].proof == nil {
			complete = false
		}
	}
	prepared := &preparedFigure6Inbound{}
	var result *figure6Result
	if complete {
		points := make([]*secp.Point, 0, len(s.cfg.Parties))
		for _, party := range s.cfg.Parties {
			reveal := s.slots[party].reveal
			point, err := secp.PointFromBytes(reveal.PublicShare)
			if err != nil {
				return nil, err
			}
			points = append(points, point)
		}
		publicKey, err := secp.PointBytes(secp.AddPoints(points...))
		if err != nil {
			return nil, err
		}
		result = &figure6Result{contribution: s.local.contribution.Clone(), publicKey: publicKey, rho: s.rho}
		prepared.cleanup = result.destroy
		prepared.result = result
	}
	prepared.commit = func() error {
		s.slots[env.From].proof = &figure6ProofPayload{Proof: payload.Proof.Clone(), Rho: payload.Rho, PlanHash: bytes.Clone(payload.PlanHash)}
		if result != nil {
			s.result = result
		}
		return nil
	}
	return prepared, nil
}
