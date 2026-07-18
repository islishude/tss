package secp256k1

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/planvalidation"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/sessiontx"
	"github.com/islishude/tss/internal/shamir"
	"github.com/islishude/tss/internal/transcript"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
	"github.com/islishude/tss/internal/zk/schnorr"
)

type auxInfoSchedule struct {
	CommitmentRound uint8
	RevealRound     uint8
	ProofRound      uint8
}

func (s auxInfoSchedule) validate() error {
	if s.CommitmentRound == invalidRound || s.RevealRound <= s.CommitmentRound || s.ProofRound <= s.RevealRound {
		return errors.New("invalid auxinfo round schedule")
	}
	return nil
}

type auxInfoStartOption struct {
	Config            tss.ThresholdConfig
	StableSID         tss.SessionID
	Limits            Limits
	SecurityParams    SecurityParams
	EnvelopeVerifier  tss.EnvelopeSignatureVerifier
	PaillierBits      int
	PlanHash          []byte
	SourceEpochID     []byte
	ExpectedPublicKey []byte
	// ExpectedContributions optionally pins every participant's Figure 7
	// constant commitment. Resharing uses it to bind the public dealer handoff
	// to the additive inputs of the new committee.
	ExpectedContributions map[tss.PartyID][]byte
	Contribution          *secret.Scalar
	Schedule              auxInfoSchedule
}

type auxInfoLocalState struct {
	contribution *secret.Scalar
	polynomial   shamir.Polynomial
	paillier     *pai.PrivateKey
	modulusPrep  *zkpai.ModulusPreparation
	schnorrPreps []*schnorr.Preparation
	dhSecrets    map[tss.PartyID]*secret.Scalar
	reveal       *auxInfoRevealPayload
}

func (s *auxInfoLocalState) destroy() {
	if s == nil {
		return
	}
	if s.contribution != nil {
		s.contribution.Destroy()
		s.contribution = nil
	}
	clearSecpPolynomial(s.polynomial)
	s.polynomial = nil
	if s.paillier != nil {
		s.paillier.Destroy()
		s.paillier = nil
	}
	if s.modulusPrep != nil {
		s.modulusPrep.Destroy()
		s.modulusPrep = nil
	}
	for i, preparation := range s.schnorrPreps {
		if preparation != nil {
			preparation.Destroy()
		}
		s.schnorrPreps[i] = nil
	}
	s.schnorrPreps = nil
	for party, dhSecret := range s.dhSecrets {
		if dhSecret != nil {
			dhSecret.Destroy()
		}
		delete(s.dhSecrets, party)
	}
	if s.reveal != nil {
		clear(s.reveal.RIDContribution)
		clear(s.reveal.Decommitment)
		s.reveal = nil
	}
}

type auxInfoPartySlot struct {
	commitment []byte
	reveal     *auxInfoRevealPayload
	proofs     *auxInfoProofsPayload
	modProof   *zkpai.ModulusProof
	factor     *zkpai.FactorProof
	share      *secret.Scalar
}

func (s *auxInfoPartySlot) destroy() {
	if s == nil {
		return
	}
	if s.share != nil {
		s.share.Destroy()
		s.share = nil
	}
	s.commitment = nil
	s.reveal = nil
	s.proofs = nil
	s.modProof = nil
	s.factor = nil
}

type auxInfoResult struct {
	secret         *secret.Scalar
	commitments    []*secp.Point
	publicKey      []byte
	partyData      map[tss.PartyID]keySharePartyData
	paillier       *pai.PrivateKey
	epoch          *EpochContext
	transcriptHash []byte
}

func (r *auxInfoResult) clone() *auxInfoResult {
	if r == nil {
		return nil
	}
	out := &auxInfoResult{
		secret:         r.secret.Clone(),
		commitments:    make([]*secp.Point, len(r.commitments)),
		publicKey:      bytes.Clone(r.publicKey),
		partyData:      make(map[tss.PartyID]keySharePartyData, len(r.partyData)),
		paillier:       r.paillier.Clone(),
		epoch:          r.epoch.Clone(),
		transcriptHash: bytes.Clone(r.transcriptHash),
	}
	for i, commitment := range r.commitments {
		out.commitments[i] = secp.Clone(commitment)
	}
	for party, data := range r.partyData {
		out.partyData[party] = data.Clone()
	}
	return out
}

func (r *auxInfoResult) destroy() {
	if r == nil {
		return
	}
	if r.secret != nil {
		r.secret.Destroy()
		r.secret = nil
	}
	if r.paillier != nil {
		r.paillier.Destroy()
		r.paillier = nil
	}
	r.commitments = nil
	r.publicKey = nil
	r.partyData = nil
	r.epoch = nil
	r.transcriptHash = nil
}

type auxInfoState struct {
	cfg                   tss.ThresholdConfig
	stableSID             tss.SessionID
	limits                Limits
	securityParams        SecurityParams
	envelopeVerifier      tss.EnvelopeSignatureVerifier
	planHash              []byte
	sourceEpochID         []byte
	expectedPublicKey     []byte
	expectedContributions map[tss.PartyID][]byte
	schedule              auxInfoSchedule
	local                 *auxInfoLocalState
	slots                 map[tss.PartyID]*auxInfoPartySlot
	revealSent            bool
	proofsSent            bool
	rid                   tss.SessionID
	epoch                 *EpochContext
	result                *auxInfoResult
	aborted               bool
}

func startAuxInfo(option auxInfoStartOption) (*auxInfoState, []tss.Envelope, error) {
	if err := option.Schedule.validate(); err != nil {
		return nil, nil, err
	}
	option.Config.Parties = option.Config.SortedParties()
	if err := option.Config.ValidateWithLimits(option.Limits.ThresholdLimits()); err != nil {
		return nil, nil, err
	}
	if !option.StableSID.Valid() {
		return nil, nil, errors.New("auxinfo stable sid is invalid")
	}
	if len(option.PlanHash) != 32 {
		return nil, nil, errors.New("auxinfo plan hash must be 32 bytes")
	}
	if len(option.SourceEpochID) != 0 && len(option.SourceEpochID) != 32 {
		return nil, nil, errors.New("auxinfo source epoch id must be absent or 32 bytes")
	}
	if option.Contribution == nil || option.Contribution.FixedLen() != secp.ScalarSize {
		return nil, nil, errors.New("invalid auxinfo additive contribution")
	}
	if len(option.ExpectedPublicKey) != 0 {
		if _, err := secp.PointFromBytes(option.ExpectedPublicKey); err != nil {
			return nil, nil, fmt.Errorf("invalid auxinfo expected public key: %w", err)
		}
	}
	state := &auxInfoState{
		cfg:                   option.Config,
		stableSID:             option.StableSID,
		limits:                option.Limits,
		securityParams:        option.SecurityParams,
		envelopeVerifier:      option.EnvelopeVerifier,
		planHash:              bytes.Clone(option.PlanHash),
		sourceEpochID:         bytes.Clone(option.SourceEpochID),
		expectedPublicKey:     bytes.Clone(option.ExpectedPublicKey),
		expectedContributions: clonePublicByteMap(option.ExpectedContributions),
		schedule:              option.Schedule,
		slots:                 make(map[tss.PartyID]*auxInfoPartySlot, len(option.Config.Parties)),
	}
	if len(state.expectedContributions) != 0 {
		if len(state.expectedContributions) != len(option.Config.Parties) {
			return nil, nil, errors.New("auxinfo expected contribution count does not match party count")
		}
		for _, party := range option.Config.Parties {
			encoded, ok := state.expectedContributions[party]
			if !ok {
				return nil, nil, fmt.Errorf("auxinfo missing expected contribution for party %d", party)
			}
			if _, err := secp.PointFromBytes(encoded); err != nil {
				return nil, nil, fmt.Errorf("auxinfo invalid expected contribution for party %d: %w", party, err)
			}
		}
	}
	for _, party := range option.Config.Parties {
		state.slots[party] = new(auxInfoPartySlot)
	}
	cleanup := sessiontx.NewCleanupStack()
	defer cleanup.Run()
	cleanup.Add(state.destroy)

	local, err := generateAuxInfoLocal(option)
	if err != nil {
		return nil, nil, err
	}
	state.local = local
	commitment, err := figure7Commitment(state.stableSID, state.cfg.SessionID, state.cfg.Self, *local.reveal, state.limits)
	if err != nil {
		return nil, nil, err
	}
	state.slots[state.cfg.Self].commitment = bytes.Clone(commitment)
	state.slots[state.cfg.Self].reveal = cloneAuxInfoReveal(local.reveal)
	payload, err := (auxInfoCommitmentPayload{Commitment: commitment, PlanHash: state.planHash}).MarshalBinaryWithLimits(state.limits)
	if err != nil {
		return nil, nil, err
	}
	env, err := newEnvelope(state.cfg, state.schedule.CommitmentRound, state.cfg.Self, tss.BroadcastPartyId, payloadAuxInfoCommitment, payload)
	clear(payload)
	if err != nil {
		return nil, nil, err
	}
	if len(state.cfg.Parties) == 1 {
		if err := state.completeSingleton(); err != nil {
			clear(env.Payload)
			return nil, nil, err
		}
	}
	cleanup.Disarm()
	return state, []tss.Envelope{env}, nil
}

// completeSingleton performs the Figure 7 transitions that are normally
// triggered by the last remote reveal, proof, and direct share. A one-party
// test committee has no peer messages, so its locally verified evaluation,
// Schnorr proofs, and modulus proof already form the complete result.
func (s *auxInfoState) completeSingleton() error {
	if s == nil || len(s.cfg.Parties) != 1 || s.cfg.Parties[0] != s.cfg.Self || s.local == nil || s.local.reveal == nil {
		return errors.New("invalid singleton auxinfo state")
	}
	reveals := map[tss.PartyID]*auxInfoRevealPayload{
		s.cfg.Self: cloneAuxInfoReveal(s.local.reveal),
	}
	prepared, err := s.prepareLocalRound3(s.cfg.Self, s.local.reveal, reveals)
	if err != nil {
		return err
	}
	defer prepared.destroy()
	if err := prepared.apply(); err != nil {
		return err
	}
	clearEnvelopePayloads(prepared.out)
	prepared.out = nil
	result, err := s.buildResult(tss.BroadcastPartyId, nil, tss.BroadcastPartyId, nil, nil, nil)
	if err != nil {
		return err
	}
	s.revealSent = true
	s.result = result
	return nil
}

func generateAuxInfoLocal(option auxInfoStartOption) (*auxInfoLocalState, error) {
	contributionScalar, err := secpScalarFromSecret(option.Contribution)
	if err != nil {
		return nil, err
	}
	poly, err := shamir.RandomPolynomial(option.Config.Reader(), option.Config.Threshold, &contributionScalar)
	if err != nil {
		return nil, err
	}
	local := &auxInfoLocalState{
		contribution: option.Contribution.Clone(),
		polynomial:   poly,
		dhSecrets:    make(map[tss.PartyID]*secret.Scalar, len(option.Config.Parties)-1),
	}
	cleanup := sessiontx.NewCleanupStack()
	defer cleanup.Run()
	cleanup.Add(local.destroy)

	paillierBits := option.PaillierBits
	if paillierBits == 0 {
		paillierBits = int(option.SecurityParams.MinPaillierBits)
	}
	if paillierBits < int(option.SecurityParams.MinPaillierBits) ||
		(option.Limits.Paillier.MaxModulusBits > 0 && paillierBits > option.Limits.Paillier.MaxModulusBits) {
		return nil, errors.New("auxinfo Paillier key size is outside allowed bounds")
	}
	paillierKey, err := generatePaillierKey(option.Config.Ctx(), option.Config.Reader(), paillierBits)
	if err != nil {
		return nil, err
	}
	local.paillier = paillierKey
	modulusPrep, err := zkpai.PrepareModulus(option.Config.Reader(), paillierKey, option.Config.Self)
	if err != nil {
		return nil, err
	}
	local.modulusPrep = modulusPrep
	ringParams, ringProof, err := generateIndependentRingPedersen(
		option.Config.Ctx(), option.Config.Reader(), paillierBits, paillierKey.N, option.Config.Self,
		func(params *zkpai.RingPedersenParams) ([]byte, error) {
			encoded, err := params.MarshalBinary()
			if err != nil {
				return nil, err
			}
			return figure7RingPedersenDomain(option.StableSID, option.Config.SessionID, option.Config.Parties, option.Config.Threshold, option.Config.Self, encoded, option.PlanHash)
		},
	)
	if err != nil {
		return nil, err
	}
	commitments := make([][]byte, len(poly))
	schnorrCommitments := make([][]byte, len(poly))
	local.schnorrPreps = make([]*schnorr.Preparation, len(poly))
	for i, coefficient := range poly {
		commitments[i], err = secp.PointBytes(secp.ScalarBaseMult(coefficient))
		if err != nil {
			return nil, err
		}
		preparation, err := schnorr.Prepare(option.Config.Reader(), commitments[i])
		if err != nil {
			return nil, err
		}
		local.schnorrPreps[i] = preparation
		schnorrCommitments[i] = preparation.Commitment()
	}
	dhKeys := make([]auxInfoDHKey, 0, len(option.Config.Parties)-1)
	for _, party := range option.Config.Parties {
		if party == option.Config.Self {
			continue
		}
		dhScalar, err := secp.RandomScalar(option.Config.Reader())
		if err != nil {
			return nil, err
		}
		dhSecret, err := secpSecretScalarFromScalar(dhScalar)
		if err != nil {
			return nil, err
		}
		local.dhSecrets[party] = dhSecret
		publicKey, err := secp.PointBytes(secp.ScalarBaseMult(dhScalar))
		if err != nil {
			return nil, err
		}
		dhKeys = append(dhKeys, auxInfoDHKey{Party: party, PublicKey: publicKey})
	}
	ridContribution, err := sampleFigureCoin(option.Config.Reader())
	if err != nil {
		return nil, err
	}
	decommitment, err := sampleFigureCoin(option.Config.Reader())
	if err != nil {
		clear(ridContribution)
		return nil, err
	}
	local.reveal = &auxInfoRevealPayload{
		PolynomialCommitments: commitments,
		DHKeys:                dhKeys,
		SchnorrCommitments:    schnorrCommitments,
		ModulusCommitment:     modulusPrep.Commitment(),
		PaillierPublicKey:     paillierKey.PublicKey.Clone(),
		RingPedersenParams:    ringParams.Clone(),
		RingPedersenProof:     ringProof.Clone(),
		RIDContribution:       ridContribution,
		Decommitment:          decommitment,
		PlanHash:              bytes.Clone(option.PlanHash),
	}
	cleanup.Disarm()
	return local, nil
}

func cloneAuxInfoReveal(in *auxInfoRevealPayload) *auxInfoRevealPayload {
	if in == nil {
		return nil
	}
	out := &auxInfoRevealPayload{
		PolynomialCommitments: tss.CloneByteSlices(in.PolynomialCommitments),
		DHKeys:                make([]auxInfoDHKey, len(in.DHKeys)),
		SchnorrCommitments:    tss.CloneByteSlices(in.SchnorrCommitments),
		ModulusCommitment:     bytes.Clone(in.ModulusCommitment),
		PaillierPublicKey:     in.PaillierPublicKey.Clone(),
		RingPedersenParams:    in.RingPedersenParams.Clone(),
		RingPedersenProof:     in.RingPedersenProof.Clone(),
		RIDContribution:       bytes.Clone(in.RIDContribution),
		Decommitment:          bytes.Clone(in.Decommitment),
		PlanHash:              bytes.Clone(in.PlanHash),
	}
	for i, key := range in.DHKeys {
		out.DHKeys[i] = key.clone()
	}
	return out
}

func cloneAuxInfoProofs(in *auxInfoProofsPayload) *auxInfoProofsPayload {
	if in == nil {
		return nil
	}
	out := &auxInfoProofsPayload{RID: in.RID, EpochID: bytes.Clone(in.EpochID), PlanHash: bytes.Clone(in.PlanHash), Proofs: make([]auxInfoSchnorrProof, len(in.Proofs))}
	for i, proof := range in.Proofs {
		out.Proofs[i] = auxInfoSchnorrProofFrom(proof.proof())
	}
	return out
}

func (s *auxInfoState) destroy() {
	if s == nil {
		return
	}
	s.aborted = true
	if s.local != nil {
		s.local.destroy()
		s.local = nil
	}
	for party, slot := range s.slots {
		if slot != nil {
			slot.destroy()
		}
		delete(s.slots, party)
	}
	if s.result != nil {
		s.result.destroy()
		s.result = nil
	}
	for party, contribution := range s.expectedContributions {
		clear(contribution)
		delete(s.expectedContributions, party)
	}
	s.epoch = nil
}

func (s *auxInfoState) completed() bool { return s != nil && !s.aborted && s.result != nil }

func (s *auxInfoState) resultSnapshot() (*auxInfoResult, bool) {
	if !s.completed() {
		return nil, false
	}
	return s.result.clone(), true
}

type preparedAuxInfoInbound struct {
	out                  []tss.Envelope
	result               *auxInfoResult
	failure              *Figure7Failure
	commit               func() error
	cleanup              func()
	committed            bool
	schnorrFinalizations []*schnorr.Finalization
	modulusFinalization  *zkpai.ModulusFinalization
}

func (p *preparedAuxInfoInbound) destroy() {
	if p == nil || p.committed {
		return
	}
	for i := range p.out {
		clear(p.out[i].Payload)
	}
	if p.cleanup != nil {
		p.cleanup()
	}
	for _, finalization := range p.schnorrFinalizations {
		if finalization != nil {
			finalization.Destroy()
		}
	}
	if p.modulusFinalization != nil {
		p.modulusFinalization.Destroy()
	}
}

func (p *preparedAuxInfoInbound) apply() error {
	if p == nil || p.committed {
		return errors.New("invalid auxinfo prepared transition")
	}
	for _, finalization := range p.schnorrFinalizations {
		if finalization != nil {
			if err := finalization.Commit(); err != nil {
				return err
			}
		}
	}
	if p.modulusFinalization != nil {
		if err := p.modulusFinalization.Commit(); err != nil {
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

func (s *auxInfoState) hasAccepted(env tss.Envelope) bool {
	if s == nil {
		return false
	}
	slot := s.slots[env.From]
	if slot == nil {
		return false
	}
	switch env.PayloadType {
	case payloadAuxInfoCommitment:
		return slot.commitment != nil
	case payloadAuxInfoReveal:
		return slot.reveal != nil
	case payloadAuxInfoProofs:
		return slot.proofs != nil
	case payloadAuxInfoDirect:
		return slot.share != nil
	default:
		return false
	}
}

func (s *auxInfoState) prepareInbound(env tss.Envelope) (*preparedAuxInfoInbound, error) {
	if s == nil || s.aborted {
		return nil, errors.New("inactive auxinfo state")
	}
	if env.From == s.cfg.Self || !s.cfg.Parties.Contains(env.From) {
		return nil, errors.New("invalid auxinfo sender")
	}
	if s.hasAccepted(env) {
		return nil, tss.ErrDuplicateMessage
	}
	switch env.PayloadType {
	case payloadAuxInfoCommitment:
		if env.Round != s.schedule.CommitmentRound || env.To != tss.BroadcastPartyId {
			return nil, errors.New("auxinfo commitment in wrong round or delivery mode")
		}
		return s.prepareCommitment(env)
	case payloadAuxInfoReveal:
		if env.Round != s.schedule.RevealRound || env.To != tss.BroadcastPartyId {
			return nil, errors.New("auxinfo reveal in wrong round or delivery mode")
		}
		return s.prepareReveal(env)
	case payloadAuxInfoProofs:
		if env.Round != s.schedule.ProofRound || env.To != tss.BroadcastPartyId {
			return nil, errors.New("auxinfo proofs in wrong round or delivery mode")
		}
		return s.prepareProofs(env)
	case payloadAuxInfoDirect:
		if env.Round != s.schedule.ProofRound || env.To != s.cfg.Self {
			return nil, errors.New("auxinfo direct message in wrong round or delivery mode")
		}
		return s.prepareDirect(env)
	case payloadAuxInfoDecryptionError:
		if env.Round != s.schedule.ProofRound || env.To != tss.BroadcastPartyId {
			return nil, errors.New("auxinfo decryption-error accusation in wrong round or delivery mode")
		}
		return s.prepareDecryptionError(env)
	default:
		return nil, fmt.Errorf("unexpected auxinfo payload type %q", env.PayloadType)
	}
}

func (s *auxInfoState) prepareCommitment(env tss.Envelope) (*preparedAuxInfoInbound, error) {
	payload, err := tss.DecodeBinaryWithLimits[auxInfoCommitmentPayload](env.Payload, s.limits)
	if err != nil {
		return nil, err
	}
	if err := planvalidation.RequireHash("auxinfo commitment", payload.PlanHash, s.planHash); err != nil {
		return nil, err
	}
	complete := true
	for _, party := range s.cfg.Parties {
		if party == env.From {
			continue
		}
		if s.slots[party].commitment == nil {
			complete = false
			break
		}
	}
	prepared := &preparedAuxInfoInbound{}
	if complete && !s.revealSent {
		revealBytes, err := s.local.reveal.MarshalBinaryWithLimits(s.limits)
		if err != nil {
			return nil, err
		}
		revealEnv, err := newEnvelope(s.cfg, s.schedule.RevealRound, s.cfg.Self, tss.BroadcastPartyId, payloadAuxInfoReveal, revealBytes)
		clear(revealBytes)
		if err != nil {
			return nil, auxInfoOutboundConstruction(err)
		}
		prepared.out = []tss.Envelope{revealEnv}
	}
	prepared.commit = func() error {
		s.slots[env.From].commitment = bytes.Clone(payload.Commitment)
		if complete {
			s.revealSent = true
		}
		return nil
	}
	return prepared, nil
}

func (s *auxInfoState) prepareReveal(env tss.Envelope) (*preparedAuxInfoInbound, error) {
	slot := s.slots[env.From]
	if slot.commitment == nil {
		return nil, auxInfoOutOfOrder("auxinfo reveal arrived before commitment")
	}
	payload, err := tss.DecodeBinaryWithLimits[auxInfoRevealPayload](env.Payload, s.limits)
	if err != nil {
		return nil, err
	}
	if err := planvalidation.RequireHash("auxinfo reveal", payload.PlanHash, s.planHash); err != nil {
		return nil, err
	}
	if len(payload.PolynomialCommitments) != s.cfg.Threshold {
		return nil, fmt.Errorf("auxinfo polynomial commitment count %d != threshold %d", len(payload.PolynomialCommitments), s.cfg.Threshold)
	}
	if err := validateAuxInfoDHKeys(payload.DHKeys, s.cfg.Parties, env.From); err != nil {
		return nil, err
	}
	if err := checkPaillierModulusBounds(payload.PaillierPublicKey, s.limits, s.securityParams); err != nil {
		return nil, err
	}
	paramsBytes, err := payload.RingPedersenParams.MarshalBinary()
	if err != nil {
		return nil, err
	}
	rpDomain, err := figure7RingPedersenDomain(s.stableSID, s.cfg.SessionID, s.cfg.Parties, s.cfg.Threshold, env.From, paramsBytes, s.planHash)
	if err != nil {
		return nil, err
	}
	if !zkpai.VerifyRingPedersen(s.securityParams, rpDomain, payload.RingPedersenParams, env.From, payload.RingPedersenProof) {
		return nil, errors.New("invalid auxinfo Ring-Pedersen proof")
	}
	commitment, err := figure7Commitment(s.stableSID, s.cfg.SessionID, env.From, *payload, s.limits)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(commitment, slot.commitment) {
		return nil, errors.New("auxinfo reveal does not open commitment")
	}

	reveals := make(map[tss.PartyID]*auxInfoRevealPayload, len(s.cfg.Parties))
	complete := true
	for _, party := range s.cfg.Parties {
		if party == env.From {
			reveals[party] = cloneAuxInfoReveal(payload)
			continue
		}
		if s.slots[party].reveal == nil {
			complete = false
			continue
		}
		reveals[party] = cloneAuxInfoReveal(s.slots[party].reveal)
	}
	if !complete || s.proofsSent {
		return &preparedAuxInfoInbound{commit: func() error {
			slot.reveal = cloneAuxInfoReveal(payload)
			return nil
		}}, nil
	}
	return s.prepareLocalRound3(env.From, payload, reveals)
}

func (s *auxInfoState) prepareLocalRound3(
	trigger tss.PartyID,
	triggerReveal *auxInfoRevealPayload,
	reveals map[tss.PartyID]*auxInfoRevealPayload,
) (*preparedAuxInfoInbound, error) {
	ridContributions := make(map[tss.PartyID][]byte, len(reveals))
	for party, reveal := range reveals {
		if reveal == nil {
			return nil, fmt.Errorf("missing auxinfo reveal from party %d", party)
		}
		ridContributions[party] = reveal.RIDContribution
	}
	rid, err := xorFigureCoins(s.cfg.Parties, ridContributions, "rid")
	if err != nil {
		return nil, err
	}
	epoch, aggregateCommitments, err := s.deriveEpoch(reveals, rid)
	if err != nil {
		return nil, err
	}
	prepared := &preparedAuxInfoInbound{}
	cleanup := sessiontx.NewCleanupStack()
	prepared.cleanup = cleanup.Run

	proofRecords := make([]auxInfoSchnorrProof, len(s.local.schnorrPreps))
	for coefficient, preparation := range s.local.schnorrPreps {
		domain, err := figure7SchnorrDomain(s.stableSID, s.cfg.SessionID, rid, epoch.EpochID, s.cfg.Parties, s.cfg.Threshold, s.cfg.Self, coefficient, s.planHash)
		if err != nil {
			prepared.destroy()
			return nil, err
		}
		coefficientSecret, err := secpSecretScalarFromScalar(s.local.polynomial[coefficient])
		if err != nil {
			prepared.destroy()
			return nil, err
		}
		finalization, err := preparation.PrepareFinalize(domain, coefficientSecret)
		coefficientSecret.Destroy()
		if err != nil {
			prepared.destroy()
			return nil, err
		}
		prepared.schnorrFinalizations = append(prepared.schnorrFinalizations, finalization)
		proofRecords[coefficient] = auxInfoSchnorrProofFrom(finalization.Proof())
	}
	modulusDomain, err := figure7ModulusDomain(s.stableSID, s.cfg.SessionID, rid, epoch.EpochID, s.cfg.Parties, s.cfg.Threshold, s.cfg.Self, s.planHash)
	if err != nil {
		prepared.destroy()
		return nil, err
	}
	modulusFinalization, err := s.local.modulusPrep.PrepareFinalize(modulusDomain)
	if err != nil {
		prepared.destroy()
		return nil, err
	}
	prepared.modulusFinalization = modulusFinalization
	localModulusProof := modulusFinalization.Proof()
	if !bytes.Equal(localModulusProof.W, s.local.reveal.ModulusCommitment) {
		prepared.destroy()
		return nil, errors.New("auxinfo modulus finalization changed first message")
	}
	proofPayload := auxInfoProofsPayload{Proofs: proofRecords, RID: rid, EpochID: bytes.Clone(epoch.EpochID), PlanHash: s.planHash}
	proofBytes, err := proofPayload.MarshalBinaryWithLimits(s.limits)
	if err != nil {
		prepared.destroy()
		return nil, err
	}
	proofEnv, err := newEnvelope(s.cfg, s.schedule.ProofRound, s.cfg.Self, tss.BroadcastPartyId, payloadAuxInfoProofs, proofBytes)
	clear(proofBytes)
	if err != nil {
		prepared.destroy()
		return nil, auxInfoOutboundConstruction(err)
	}
	prepared.out = append(prepared.out, proofEnv)

	identifierBytes, ok := epoch.Identifier(s.cfg.Self)
	if !ok {
		prepared.destroy()
		return nil, errors.New("missing local auxinfo epoch identifier")
	}
	localEvaluation, err := evaluateFigure7Polynomial(s.local.polynomial, epoch, s.cfg.Self)
	if err != nil {
		clear(identifierBytes)
		prepared.destroy()
		return nil, err
	}
	localShare, err := secpSecretScalarFromScalarAllowZero(localEvaluation)
	if err != nil {
		clear(identifierBytes)
		prepared.destroy()
		return nil, err
	}
	cleanup.Add(localShare.Destroy)
	if err := verifyFigure7Share(s.local.reveal.PolynomialCommitments, identifierBytes, localEvaluation.Bytes()); err != nil {
		clear(identifierBytes)
		prepared.destroy()
		return nil, err
	}
	clear(identifierBytes)

	for _, receiver := range s.cfg.Parties {
		if receiver == s.cfg.Self {
			continue
		}
		receiverReveal := reveals[receiver]
		factorDomain, err := figure7FactorDomain(s.stableSID, s.cfg.SessionID, rid, epoch.EpochID, s.cfg.Parties, s.cfg.Threshold, s.cfg.Self, receiver, s.planHash)
		if err != nil {
			prepared.destroy()
			return nil, err
		}
		factorProof, err := zkpai.ProveFactor(s.securityParams, factorDomain, s.local.paillier, receiverReveal.RingPedersenParams, s.cfg.Reader())
		if err != nil {
			prepared.destroy()
			return nil, err
		}
		evaluation, err := evaluateFigure7Polynomial(s.local.polynomial, epoch, receiver)
		if err != nil {
			prepared.destroy()
			return nil, err
		}
		peerDH, ok := auxInfoDHKeyFor(receiverReveal.DHKeys, s.cfg.Self)
		if !ok {
			prepared.destroy()
			return nil, fmt.Errorf("missing auxinfo DH key from receiver %d", receiver)
		}
		shared, err := figure7DHSharedSecret(peerDH, s.local.dhSecrets[receiver])
		clear(peerDH)
		if err != nil {
			prepared.destroy()
			return nil, err
		}
		mask, err := deriveFigure7DHMask(s.stableSID, s.cfg.SessionID, rid, epoch.EpochID, s.cfg.Self, receiver, shared, s.planHash)
		clear(shared)
		if err != nil {
			prepared.destroy()
			return nil, err
		}
		directPayload := auxInfoDirectPayload{
			ModulusProof: localModulusProof.Clone(),
			FactorProof:  factorProof.Clone(),
			MaskedShare:  maskFigure7Share(evaluation, mask),
			RID:          rid,
			EpochID:      bytes.Clone(epoch.EpochID),
			PlanHash:     s.planHash,
		}
		directBytes, err := directPayload.MarshalBinaryWithLimits(s.limits)
		if err != nil {
			prepared.destroy()
			return nil, err
		}
		directEnv, err := newEnvelope(s.cfg, s.schedule.ProofRound, s.cfg.Self, receiver, payloadAuxInfoDirect, directBytes)
		clear(directBytes)
		if err != nil {
			prepared.destroy()
			return nil, auxInfoOutboundConstruction(err)
		}
		prepared.out = append(prepared.out, directEnv)
	}
	prepared.commit = func() error {
		s.slots[trigger].reveal = cloneAuxInfoReveal(triggerReveal)
		s.rid = rid
		s.epoch = epoch.Clone()
		s.proofsSent = true
		s.slots[s.cfg.Self].proofs = cloneAuxInfoProofs(&proofPayload)
		s.slots[s.cfg.Self].modProof = localModulusProof.Clone()
		s.slots[s.cfg.Self].share = localShare
		cleanup.Disarm()
		_ = aggregateCommitments
		return nil
	}
	return prepared, nil
}

func (s *auxInfoState) deriveEpoch(
	reveals map[tss.PartyID]*auxInfoRevealPayload,
	rid tss.SessionID,
) (*EpochContext, []*secp.Point, error) {
	aggregate, err := aggregateAuxInfoCommitments(s.cfg.Parties, s.cfg.Threshold, reveals)
	if err != nil {
		return nil, nil, err
	}
	if len(s.expectedContributions) != 0 {
		for _, party := range s.cfg.Parties {
			reveal := reveals[party]
			if reveal == nil || len(reveal.PolynomialCommitments) == 0 ||
				!bytes.Equal(reveal.PolynomialCommitments[0], s.expectedContributions[party]) {
				return nil, nil, fmt.Errorf("auxinfo constant commitment for party %d does not match resharing handoff", party)
			}
		}
	}
	publicKey, err := secp.PointBytes(aggregate[0])
	if err != nil {
		return nil, nil, err
	}
	if len(s.expectedPublicKey) != 0 && !bytes.Equal(publicKey, s.expectedPublicKey) {
		return nil, nil, errors.New("auxinfo polynomial constants changed expected group public key")
	}
	partyData := make(map[tss.PartyID]keySharePartyData, len(s.cfg.Parties))
	publicShares := make([]EpochPublicShare, len(s.cfg.Parties))
	for i, party := range s.cfg.Parties {
		reveal := reveals[party]
		partyData[party] = keySharePartyData{
			PaillierPublicKey:  reveal.PaillierPublicKey.Clone(),
			RingPedersenParams: reveal.RingPedersenParams.Clone(),
		}
		identifier, err := DeriveEpochIdentifier(s.stableSID, rid, party)
		if err != nil {
			return nil, nil, err
		}
		point, err := evaluateCommitmentPointsAtIdentifier(aggregate, identifier)
		if err != nil {
			return nil, nil, err
		}
		encoded, err := secp.PointBytes(point)
		if err != nil {
			return nil, nil, err
		}
		publicShares[i] = EpochPublicShare{Party: party, PublicKey: encoded}
	}
	auxiliaryDigest, err := computeEpochAuxiliaryDigest(s.cfg.Parties, partyData)
	if err != nil {
		return nil, nil, err
	}
	epoch, err := NewEpochContext(EpochContextOption{
		SID:             s.stableSID,
		RID:             rid,
		Threshold:       s.cfg.Threshold,
		Parties:         s.cfg.Parties,
		PublicShares:    publicShares,
		AuxiliaryDigest: auxiliaryDigest,
		SourceEpochID:   s.sourceEpochID,
	})
	if err != nil {
		return nil, nil, err
	}
	return epoch, aggregate, nil
}

func clonePublicByteMap(in map[tss.PartyID][]byte) map[tss.PartyID][]byte {
	if len(in) == 0 {
		return nil
	}
	out := make(map[tss.PartyID][]byte, len(in))
	for party, value := range in {
		out[party] = bytes.Clone(value)
	}
	return out
}

func aggregateAuxInfoCommitments(
	parties tss.PartySet,
	threshold int,
	reveals map[tss.PartyID]*auxInfoRevealPayload,
) ([]*secp.Point, error) {
	out := make([]*secp.Point, threshold)
	for coefficient := range threshold {
		points := make([]*secp.Point, 0, len(parties))
		for _, party := range parties {
			reveal := reveals[party]
			if reveal == nil || len(reveal.PolynomialCommitments) != threshold {
				return nil, fmt.Errorf("invalid auxinfo polynomial commitments for party %d", party)
			}
			point, err := secp.PointFromBytes(reveal.PolynomialCommitments[coefficient])
			if err != nil {
				return nil, err
			}
			points = append(points, point)
		}
		out[coefficient] = secp.AddPoints(points...)
	}
	return out, nil
}

func (s *auxInfoState) prepareProofs(env tss.Envelope) (*preparedAuxInfoInbound, error) {
	if s.epoch == nil || !s.proofsSent {
		return nil, auxInfoOutOfOrder("auxinfo proofs arrived before all reveals")
	}
	payload, err := tss.DecodeBinaryWithLimits[auxInfoProofsPayload](env.Payload, s.limits)
	if err != nil {
		return nil, err
	}
	if err := planvalidation.RequireHash("auxinfo proofs", payload.PlanHash, s.planHash); err != nil {
		return nil, err
	}
	if payload.RID != s.rid || !bytes.Equal(payload.EpochID, s.epoch.EpochID) {
		return nil, errors.New("auxinfo proof binding mismatch")
	}
	if len(payload.Proofs) != s.cfg.Threshold {
		return nil, errors.New("auxinfo Schnorr proof count does not match threshold")
	}
	reveal := s.slots[env.From].reveal
	if reveal == nil {
		return nil, errors.New("auxinfo proofs have no sender reveal")
	}
	for coefficient, record := range payload.Proofs {
		proof := record.proof()
		if !bytes.Equal(proof.Commitment, reveal.SchnorrCommitments[coefficient]) {
			return nil, fmt.Errorf("auxinfo Schnorr first message mismatch at coefficient %d", coefficient)
		}
		domain, err := figure7SchnorrDomain(s.stableSID, s.cfg.SessionID, s.rid, s.epoch.EpochID, s.cfg.Parties, s.cfg.Threshold, env.From, coefficient, s.planHash)
		if err != nil {
			return nil, err
		}
		if !schnorr.Verify(domain, reveal.PolynomialCommitments[coefficient], proof) {
			return nil, fmt.Errorf("invalid auxinfo Schnorr proof at coefficient %d", coefficient)
		}
	}
	prepared := &preparedAuxInfoInbound{}
	var result *auxInfoResult
	if s.allAuxInfoSharesExcept(tss.BroadcastPartyId) && s.allAuxInfoProofsExcept(env.From) {
		result, err = s.buildResult(env.From, payload, tss.BroadcastPartyId, nil, nil, nil)
		if err != nil {
			return nil, err
		}
		prepared.cleanup = result.destroy
		prepared.result = result
	}
	prepared.commit = func() error {
		s.slots[env.From].proofs = cloneAuxInfoProofs(payload)
		if result != nil {
			s.result = result
		}
		return nil
	}
	return prepared, nil
}

func (s *auxInfoState) prepareDirect(env tss.Envelope) (*preparedAuxInfoInbound, error) {
	if s.epoch == nil || !s.proofsSent {
		return nil, auxInfoOutOfOrder("auxinfo direct message arrived before all reveals")
	}
	payload, err := tss.DecodeBinaryWithLimits[auxInfoDirectPayload](env.Payload, s.limits)
	if err != nil {
		return nil, err
	}
	if err := planvalidation.RequireHash("auxinfo direct", payload.PlanHash, s.planHash); err != nil {
		return nil, err
	}
	if payload.RID != s.rid {
		return nil, errors.New("auxinfo direct binding mismatch")
	}
	if !bytes.Equal(payload.EpochID, s.epoch.EpochID) {
		return nil, errors.New("auxinfo direct epoch mismatch")
	}
	reveal := s.slots[env.From].reveal
	if reveal == nil {
		return nil, errors.New("auxinfo direct message has no sender reveal")
	}
	if !bytes.Equal(payload.ModulusProof.W, reveal.ModulusCommitment) {
		return nil, errors.New("auxinfo modulus proof first message mismatch")
	}
	modulusDomain, err := figure7ModulusDomain(s.stableSID, s.cfg.SessionID, s.rid, s.epoch.EpochID, s.cfg.Parties, s.cfg.Threshold, env.From, s.planHash)
	if err != nil {
		return nil, err
	}
	if !zkpai.VerifyModulus(modulusDomain, reveal.PaillierPublicKey, env.From, payload.ModulusProof) {
		return nil, errors.New("invalid auxinfo modulus proof")
	}
	localReveal := s.slots[s.cfg.Self].reveal
	factorDomain, err := figure7FactorDomain(s.stableSID, s.cfg.SessionID, s.rid, s.epoch.EpochID, s.cfg.Parties, s.cfg.Threshold, env.From, s.cfg.Self, s.planHash)
	if err != nil {
		return nil, err
	}
	if err := zkpai.VerifyFactor(s.securityParams, factorDomain, zkpai.FactorStatement{
		ProverPaillierN: reveal.PaillierPublicKey,
		VerifierAux:     localReveal.RingPedersenParams,
	}, payload.FactorProof); err != nil {
		return nil, fmt.Errorf("invalid auxinfo factor proof: %w", err)
	}
	peerDH, ok := auxInfoDHKeyFor(reveal.DHKeys, s.cfg.Self)
	if !ok {
		return nil, errors.New("auxinfo sender omitted local DH key")
	}
	shared, err := figure7DHSharedSecret(peerDH, s.local.dhSecrets[env.From])
	clear(peerDH)
	if err != nil {
		return nil, err
	}
	mask, err := deriveFigure7DHMask(s.stableSID, s.cfg.SessionID, s.rid, s.epoch.EpochID, env.From, s.cfg.Self, shared, s.planHash)
	clear(shared)
	if err != nil {
		return nil, err
	}
	shareValue, err := unmaskFigure7Share(payload.MaskedShare, mask)
	if err != nil {
		return nil, err
	}
	defer shareValue.Set(secp.ScalarZero())
	identifier, ok := s.epoch.Identifier(s.cfg.Self)
	if !ok {
		return nil, errors.New("missing local auxinfo identifier")
	}
	if err := verifyFigure7Share(reveal.PolynomialCommitments, identifier, shareValue.Bytes()); err != nil {
		clear(identifier)
		if errors.Is(err, errFigure7ShareMismatch) {
			return s.prepareDecryptionErrorBroadcast(env)
		}
		return nil, err
	}
	clear(identifier)
	share, err := secpSecretScalarFromScalarAllowZero(shareValue)
	if err != nil {
		return nil, err
	}
	prepared := &preparedAuxInfoInbound{cleanup: share.Destroy}
	var result *auxInfoResult
	if s.allAuxInfoProofsExcept(tss.BroadcastPartyId) && s.allAuxInfoSharesExcept(env.From) {
		result, err = s.buildResult(tss.BroadcastPartyId, nil, env.From, share, payload.ModulusProof, payload.FactorProof)
		if err != nil {
			prepared.destroy()
			return nil, err
		}
		prepared.cleanup = func() {
			share.Destroy()
			result.destroy()
		}
		prepared.result = result
	}
	prepared.commit = func() error {
		slot := s.slots[env.From]
		slot.modProof = payload.ModulusProof.Clone()
		slot.factor = payload.FactorProof.Clone()
		slot.share = share
		if result != nil {
			s.result = result
		}
		return nil
	}
	return prepared, nil
}

func (s *auxInfoState) prepareDecryptionErrorBroadcast(direct tss.Envelope) (*preparedAuxInfoInbound, error) {
	if s.local == nil || s.epoch == nil {
		return nil, errors.New("auxinfo decryption-error witness is unavailable")
	}
	dhSecret := s.local.dhSecrets[direct.From]
	if dhSecret == nil {
		return nil, errors.New("auxinfo decryption-error DH witness is unavailable")
	}
	dhExponent := dhSecret.FixedBytes()
	defer clear(dhExponent)
	envelopeLimits := tss.DefaultEnvelopeLimits()
	signedDirect, err := direct.MarshalBinaryWithLimits(envelopeLimits)
	if err != nil {
		return nil, errors.New("marshal authenticated auxinfo direct envelope")
	}
	defer clear(signedDirect)
	accusation := &auxInfoDecryptionErrorPayload{
		Accused:              direct.From,
		DHExponent:           bytes.Clone(dhExponent),
		SignedDirectEnvelope: bytes.Clone(signedDirect),
		SID:                  s.stableSID,
		RID:                  s.rid,
		EpochID:              bytes.Clone(s.epoch.EpochID),
		PlanHash:             bytes.Clone(s.planHash),
	}
	defer accusation.destroy()
	encoded, err := accusation.MarshalBinaryWithLimits(s.limits)
	if err != nil {
		return nil, err
	}
	defer clear(encoded)
	out, err := newEnvelope(s.cfg, s.schedule.ProofRound, s.cfg.Self, tss.BroadcastPartyId, payloadAuxInfoDecryptionError, encoded)
	if err != nil {
		return nil, auxInfoOutboundConstruction(err)
	}
	digest := direct.Digest()
	failure := &Figure7Failure{
		Class:                Figure7FailureDecryptionError,
		Reporter:             s.cfg.Self,
		Accused:              direct.From,
		DirectEnvelopeDigest: bytes.Clone(digest[:]),
	}
	return s.prepareTerminalFigure7Failure(failure, []tss.Envelope{out}), nil
}

func (s *auxInfoState) prepareDecryptionError(env tss.Envelope) (*preparedAuxInfoInbound, error) {
	if s.epoch == nil || !s.proofsSent {
		return nil, auxInfoOutOfOrder("auxinfo decryption-error accusation arrived before all reveals")
	}
	payload, err := tss.DecodeBinaryWithLimits[auxInfoDecryptionErrorPayload](env.Payload, s.limits)
	if err != nil {
		return nil, err
	}
	defer payload.destroy()
	directDigest, mismatch, verifyErr := s.verifyDecryptionError(env.From, payload)
	failure := &Figure7Failure{
		Class:                Figure7FailureFalseAccusation,
		Reporter:             env.From,
		Accused:              env.From,
		DirectEnvelopeDigest: directDigest,
	}
	if verifyErr == nil && mismatch {
		failure.Class = Figure7FailureDecryptionError
		failure.Accused = payload.Accused
	}
	return s.prepareTerminalFigure7Failure(failure, nil), nil
}

func (s *auxInfoState) verifyDecryptionError(reporter tss.PartyID, payload *auxInfoDecryptionErrorPayload) ([]byte, bool, error) {
	if payload == nil || payload.Accused == reporter || !s.cfg.Parties.Contains(payload.Accused) {
		return nil, false, errors.New("invalid auxinfo decryption-error parties")
	}
	if payload.SID != s.stableSID || payload.RID != s.rid || !bytes.Equal(payload.EpochID, s.epoch.EpochID) || !bytes.Equal(payload.PlanHash, s.planHash) {
		return nil, false, errors.New("auxinfo decryption-error binding mismatch")
	}
	envelopeLimits := tss.DefaultEnvelopeLimits()
	direct, err := tss.UnmarshalEnvelopeWithLimits(payload.SignedDirectEnvelope, envelopeLimits)
	if err != nil {
		return nil, false, errors.New("decode auxinfo decryption-error signed envelope")
	}
	canonical, err := direct.MarshalBinaryWithLimits(envelopeLimits)
	if err != nil {
		return nil, false, errors.New("marshal auxinfo decryption-error signed envelope")
	}
	defer clear(canonical)
	if !bytes.Equal(canonical, payload.SignedDirectEnvelope) {
		return nil, false, errors.New("non-canonical auxinfo decryption-error signed envelope")
	}
	digest := direct.Digest()
	digestBytes := bytes.Clone(digest[:])
	if direct.Protocol != tss.ProtocolCGGMP21Secp256k1 || direct.SessionID != s.cfg.SessionID ||
		direct.Round != s.schedule.ProofRound || direct.PayloadType != payloadAuxInfoDirect ||
		direct.From != payload.Accused || direct.To != reporter {
		return digestBytes, false, errors.New("auxinfo decryption-error direct envelope context mismatch")
	}
	if err := tss.VerifyEnvelopeSignature(direct, s.envelopeVerifier); err != nil {
		return digestBytes, false, errors.New("auxinfo decryption-error direct envelope authentication failed")
	}
	directPayload, err := tss.DecodeBinaryWithLimits[auxInfoDirectPayload](direct.Payload, s.limits)
	if err != nil {
		return digestBytes, false, errors.New("auxinfo decryption-error direct payload is invalid")
	}
	if directPayload.RID != s.rid || !bytes.Equal(directPayload.EpochID, s.epoch.EpochID) || !bytes.Equal(directPayload.PlanHash, s.planHash) {
		return digestBytes, false, errors.New("auxinfo decryption-error direct payload binding mismatch")
	}
	reporterReveal := s.slots[reporter].reveal
	accusedReveal := s.slots[payload.Accused].reveal
	if reporterReveal == nil || accusedReveal == nil {
		return digestBytes, false, errors.New("auxinfo decryption-error reveal state is incomplete")
	}
	exponent, err := secp.ScalarFromBytes(payload.DHExponent)
	if err != nil {
		return digestBytes, false, errors.New("invalid auxinfo decryption-error DH exponent")
	}
	defer exponent.Set(secp.ScalarZero())
	reporterDH, ok := auxInfoDHKeyFor(reporterReveal.DHKeys, payload.Accused)
	if !ok {
		return digestBytes, false, errors.New("auxinfo decryption-error reporter DH key is missing")
	}
	defer clear(reporterDH)
	expectedReporterDH, err := secp.PointBytes(secp.ScalarBaseMult(exponent))
	if err != nil {
		return digestBytes, false, errors.New("derive auxinfo decryption-error reporter DH key")
	}
	defer clear(expectedReporterDH)
	if !bytes.Equal(expectedReporterDH, reporterDH) {
		return digestBytes, false, errors.New("auxinfo decryption-error exponent does not open reporter DH key")
	}
	accusedDH, ok := auxInfoDHKeyFor(accusedReveal.DHKeys, reporter)
	if !ok {
		return digestBytes, false, errors.New("auxinfo decryption-error accused DH key is missing")
	}
	defer clear(accusedDH)
	accusedPoint, err := secp.PointFromBytes(accusedDH)
	if err != nil {
		return digestBytes, false, errors.New("invalid auxinfo decryption-error accused DH key")
	}
	shared, err := secp.PointBytes(secp.ScalarMult(accusedPoint, exponent))
	if err != nil {
		return digestBytes, false, errors.New("derive auxinfo decryption-error shared point")
	}
	defer clear(shared)
	mask, err := deriveFigure7DHMask(s.stableSID, s.cfg.SessionID, s.rid, s.epoch.EpochID, payload.Accused, reporter, shared, s.planHash)
	if err != nil {
		return digestBytes, false, errors.New("derive auxinfo decryption-error mask")
	}
	defer mask.Set(secp.ScalarZero())
	share, err := unmaskFigure7Share(directPayload.MaskedShare, mask)
	if err != nil {
		return digestBytes, false, errors.New("unmask auxinfo decryption-error share")
	}
	defer share.Set(secp.ScalarZero())
	identifier, ok := s.epoch.Identifier(reporter)
	if !ok {
		return digestBytes, false, errors.New("auxinfo decryption-error identifier is missing")
	}
	defer clear(identifier)
	err = verifyFigure7Share(accusedReveal.PolynomialCommitments, identifier, share.Bytes())
	if err == nil {
		return digestBytes, false, nil
	}
	if errors.Is(err, errFigure7ShareMismatch) {
		return digestBytes, true, nil
	}
	return digestBytes, false, errors.New("verify auxinfo decryption-error share relation")
}

func (s *auxInfoState) prepareTerminalFigure7Failure(failure *Figure7Failure, out []tss.Envelope) *preparedAuxInfoInbound {
	prepared := &preparedAuxInfoInbound{out: out, failure: cloneFigure7Failure(failure)}
	prepared.commit = func() error {
		s.destroy()
		return nil
	}
	return prepared
}

func (s *auxInfoState) allAuxInfoProofsExcept(except tss.PartyID) bool {
	for _, party := range s.cfg.Parties {
		if party == except {
			continue
		}
		if s.slots[party].proofs == nil {
			return false
		}
	}
	return true
}

func (s *auxInfoState) allAuxInfoSharesExcept(except tss.PartyID) bool {
	for _, party := range s.cfg.Parties {
		if party == except {
			continue
		}
		if s.slots[party].share == nil || s.slots[party].modProof == nil {
			return false
		}
	}
	return true
}

func (s *auxInfoState) buildResult(
	proofParty tss.PartyID,
	proofOverride *auxInfoProofsPayload,
	shareParty tss.PartyID,
	shareOverride *secret.Scalar,
	modulusOverride *zkpai.ModulusProof,
	factorOverride *zkpai.FactorProof,
) (*auxInfoResult, error) {
	if s.epoch == nil {
		return nil, errors.New("missing auxinfo epoch")
	}
	reveals := make(map[tss.PartyID]*auxInfoRevealPayload, len(s.cfg.Parties))
	for _, party := range s.cfg.Parties {
		reveals[party] = s.slots[party].reveal
	}
	commitments, err := aggregateAuxInfoCommitments(s.cfg.Parties, s.cfg.Threshold, reveals)
	if err != nil {
		return nil, err
	}
	publicKey, err := secp.PointBytes(commitments[0])
	if err != nil {
		return nil, err
	}
	aggregateSecret := secp.ScalarZero()
	for _, party := range s.cfg.Parties {
		share := s.slots[party].share
		if party == shareParty {
			share = shareOverride
		}
		if share == nil {
			return nil, fmt.Errorf("missing auxinfo share from party %d", party)
		}
		value, err := secpScalarFromSecretAllowZero(share)
		if err != nil {
			return nil, err
		}
		aggregateSecret = secp.ScalarAdd(aggregateSecret, value)
	}
	secretScalar, err := secpSecretScalarFromScalar(aggregateSecret)
	if err != nil {
		return nil, errors.New("auxinfo aggregate share is zero")
	}
	cleanup := sessiontx.NewCleanupStack()
	defer cleanup.Run()
	cleanup.Add(secretScalar.Destroy)
	localPublic, ok := s.epoch.PublicShare(s.cfg.Self)
	if !ok {
		return nil, errors.New("missing local auxinfo public share")
	}
	if !secp.Equal(secp.ScalarBaseMult(aggregateSecret), mustAuxInfoPoint(localPublic.PublicKey)) {
		return nil, errors.New("auxinfo aggregate secret does not match epoch public share")
	}
	partyData := make(map[tss.PartyID]keySharePartyData, len(s.cfg.Parties))
	for _, party := range s.cfg.Parties {
		slot := s.slots[party]
		modProof := slot.modProof
		factorProof := slot.factor
		if party == shareParty {
			modProof = modulusOverride
			factorProof = factorOverride
		}
		if modProof == nil {
			return nil, fmt.Errorf("missing auxinfo modulus proof for party %d", party)
		}
		verificationShare, ok := s.epoch.PublicShare(party)
		if !ok {
			return nil, fmt.Errorf("missing auxinfo public share for party %d", party)
		}
		partyData[party] = keySharePartyData{
			VerificationShare:   bytes.Clone(verificationShare.PublicKey),
			PaillierPublicKey:   slot.reveal.PaillierPublicKey.Clone(),
			PaillierProof:       modProof.Clone(),
			RingPedersenParams:  slot.reveal.RingPedersenParams.Clone(),
			RingPedersenProof:   slot.reveal.RingPedersenProof.Clone(),
			PaillierFactorProof: factorProof.Clone(),
		}
	}
	partyData[s.cfg.Self] = func(data keySharePartyData) keySharePartyData {
		data.PaillierFactorProof = nil
		return data
	}(partyData[s.cfg.Self])
	transcriptHash, err := s.auxInfoTranscriptHash(commitments, proofParty, proofOverride, shareParty, modulusOverride)
	if err != nil {
		return nil, err
	}
	result := &auxInfoResult{
		secret:         secretScalar,
		commitments:    commitments,
		publicKey:      publicKey,
		partyData:      partyData,
		paillier:       s.local.paillier.Clone(),
		epoch:          s.epoch.Clone(),
		transcriptHash: transcriptHash,
	}
	cleanup.Disarm()
	return result, nil
}

func mustAuxInfoPoint(encoded []byte) *secp.Point {
	point, err := secp.PointFromBytes(encoded)
	if err != nil {
		return secp.NewInfinity()
	}
	return point
}

func (s *auxInfoState) auxInfoTranscriptHash(
	commitments []*secp.Point,
	proofParty tss.PartyID,
	proofOverride *auxInfoProofsPayload,
	shareParty tss.PartyID,
	modulusOverride *zkpai.ModulusProof,
) ([]byte, error) {
	commitmentBytes, err := secp.CommitmentPointsBytes(commitments)
	if err != nil {
		return nil, err
	}
	t := transcript.New(figure7TranscriptHashLabel)
	t.AppendBytes("stable_sid", s.stableSID[:])
	t.AppendBytes("run_session_id", s.cfg.SessionID[:])
	t.AppendBytes("rid", s.rid[:])
	t.AppendBytes("epoch_id", s.epoch.EpochID)
	t.AppendBytes("plan_hash", s.planHash)
	t.AppendBytesList("aggregate_commitments", commitmentBytes)
	for _, party := range s.cfg.Parties {
		slot := s.slots[party]
		commitment, err := figure7Commitment(s.stableSID, s.cfg.SessionID, party, *slot.reveal, s.limits)
		if err != nil {
			return nil, err
		}
		proofs := slot.proofs
		if party == proofParty {
			proofs = proofOverride
		}
		if proofs == nil {
			return nil, fmt.Errorf("missing auxinfo proofs for transcript party %d", party)
		}
		proofBytes, err := proofs.MarshalBinaryWithLimits(s.limits)
		if err != nil {
			return nil, err
		}
		modProof := slot.modProof
		if party == shareParty {
			modProof = modulusOverride
		}
		if modProof == nil {
			return nil, fmt.Errorf("missing auxinfo modulus proof for transcript party %d", party)
		}
		modBytes, err := modProof.MarshalBinary()
		if err != nil {
			return nil, err
		}
		t.AppendUint32("party", party)
		t.AppendBytes("opening_commitment", commitment)
		t.AppendBytes("schnorr_proofs", proofBytes)
		t.AppendBytes("modulus_proof", modBytes)
	}
	return t.Sum(), nil
}
