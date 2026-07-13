package ed25519

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"sync"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/bip32util"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
	"github.com/islishude/tss/internal/inmemoryrun"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/transcript"
	"github.com/islishude/tss/internal/wire"
)

const (
	trustedDealerImportPlanWireType             = "frost.ed25519.trusted-dealer-import-plan"
	trustedDealerImportPlanWireVersion   uint16 = 1
	trustedDealerContributionWireType           = "frost.ed25519.trusted-dealer-contribution"
	trustedDealerContributionWireVersion uint16 = 1
	trustedDealerImportPlanDigestLabel          = "frost-ed25519-trusted-dealer-import-plan-v1"
)

// TrustedDealerImportOption configures creation of a trusted-dealer import.
// ChainCode may be nil to request a fresh random chain code.
type TrustedDealerImportOption struct {
	SessionID tss.SessionID
	Parties   tss.PartySet
	Threshold int
	ChainCode []byte
	Limits    *Limits
}

type trustedDealerCommitment struct {
	Party              tss.PartyID    `wire:"1,u32"`
	ConstantCommitment PublicKeyPoint `wire:"2,custom,len=32,max_bytes=point"`
	ChainCodeCommit    []byte         `wire:"3,bytes,len=32"`
}

type trustedDealerImportPlanState struct {
	SessionID   tss.SessionID             `wire:"1,bytes,len=32"`
	Threshold   int                       `wire:"2,u32"`
	Parties     tss.PartySet              `wire:"3,u32list,max_items=parties"`
	PublicKey   PublicKeyPoint            `wire:"4,custom,len=32,max_bytes=point"`
	ChainCode   []byte                    `wire:"5,bytes,len=32"`
	Commitments []trustedDealerCommitment `wire:"6,recordlist,max_items=parties"`
}

// TrustedDealerImportPlan is the public, canonical intent shared by every
// participant in a trusted-dealer import run.
type TrustedDealerImportPlan struct {
	state  *trustedDealerImportPlanState
	limits Limits
}

// TrustedDealerImportPlanSnapshot is a caller-owned public plan snapshot.
type TrustedDealerImportPlanSnapshot struct {
	SessionID   tss.SessionID
	Threshold   int
	Parties     tss.PartySet
	PublicKey   []byte
	ChainCode   []byte
	Commitments map[tss.PartyID][]byte
}

type trustedDealerContributionState struct {
	SessionID tss.SessionID  `wire:"1,bytes,len=32"`
	Party     tss.PartyID    `wire:"2,u32"`
	Scalar    *secret.Scalar `wire:"3,custom,len=32,max_bytes=scalar"`
	ChainCode []byte         `wire:"4,bytes,len=32"`
	PlanHash  []byte         `wire:"5,bytes,len=32"`
}

type contributionLifecycle struct {
	mu     sync.Mutex
	status uint8
}

// TrustedDealerContribution is one session- and party-bound secret import
// contribution. It must be distributed only through a confidential channel.
type TrustedDealerContribution struct {
	state     *trustedDealerContributionState
	lifecycle *contributionLifecycle
}

// NewTrustedDealerImport splits secret into non-zero additive contributions
// and returns the public plan plus one secret contribution per party.
func NewTrustedDealerImport(secretKey *SecretKey, option TrustedDealerImportOption, reader io.Reader) (*TrustedDealerImportPlan, map[tss.PartyID]*TrustedDealerContribution, error) {
	if err := secretKey.validate(); err != nil {
		return nil, nil, err
	}
	limits := limitsOrDefault(option.Limits)
	parties, err := validatePlanPartySetVerbose(option.Parties, option.Threshold, limits)
	if err != nil {
		return nil, nil, invalidPlanConfig(0, err)
	}
	if !option.SessionID.Valid() {
		return nil, nil, invalidPlanConfig(0, tss.ErrInvalidSessionID)
	}
	if reader == nil {
		reader = rand.Reader
	}
	targetChainCode := bytes.Clone(option.ChainCode)
	if targetChainCode == nil {
		targetChainCode = make([]byte, bip32util.ChainCodeSize)
		if _, err := io.ReadFull(reader, targetChainCode); err != nil {
			return nil, nil, err
		}
	}
	if len(targetChainCode) != bip32util.ChainCodeSize {
		clear(targetChainCode)
		return nil, nil, fmt.Errorf("chain code must be %d bytes", bip32util.ChainCodeSize)
	}
	targetScalar, err := edScalarFromSecret(secretKey.state.scalar)
	if err != nil {
		clear(targetChainCode)
		return nil, nil, err
	}
	defer targetScalar.Set(fed.NewScalar())
	scalars, err := splitFROSTDealerScalar(reader, targetScalar, len(parties))
	if err != nil {
		clear(targetChainCode)
		return nil, nil, err
	}
	defer clearScalars(scalars)
	chainCodes, err := splitDealerChainCode(reader, targetChainCode, parties)
	if err != nil {
		clear(targetChainCode)
		return nil, nil, err
	}
	defer func() {
		for _, value := range chainCodes {
			clear(value)
		}
	}()
	publicKey, err := secretKey.PublicKey()
	if err != nil {
		clear(targetChainCode)
		return nil, nil, err
	}
	commitments := make([]trustedDealerCommitment, 0, len(parties))
	for i, party := range parties {
		constant, err := newPublicKeyPointFromPoint(fed.NewIdentityPoint().ScalarBaseMult(scalars[i]))
		if err != nil {
			clear(targetChainCode)
			return nil, nil, err
		}
		commitments = append(commitments, trustedDealerCommitment{
			Party:              party,
			ConstantCommitment: constant,
			ChainCodeCommit: bip32util.ChainCodeCommitment(
				frostChainCodeCommitLabel,
				option.SessionID,
				party,
				chainCodes[party],
			),
		})
	}
	plan := &TrustedDealerImportPlan{state: &trustedDealerImportPlanState{
		SessionID:   option.SessionID,
		Threshold:   option.Threshold,
		Parties:     parties.Clone(),
		PublicKey:   publicKey,
		ChainCode:   bytes.Clone(targetChainCode),
		Commitments: commitments,
	}, limits: limits}
	clear(targetChainCode)
	if err := plan.ValidateWithLimits(limits); err != nil {
		return nil, nil, err
	}
	planHash, err := plan.Digest()
	if err != nil {
		return nil, nil, err
	}
	contributions := make(map[tss.PartyID]*TrustedDealerContribution, len(parties))
	for i, party := range parties {
		value, err := newEdSecretScalarFromFed(scalars[i])
		if err != nil {
			destroyFROSTContributions(contributions)
			return nil, nil, err
		}
		contributions[party] = &TrustedDealerContribution{
			state: &trustedDealerContributionState{
				SessionID: option.SessionID,
				Party:     party,
				Scalar:    value,
				ChainCode: bytes.Clone(chainCodes[party]),
				PlanHash:  bytes.Clone(planHash),
			},
			lifecycle: new(contributionLifecycle),
		}
	}
	return plan, contributions, nil
}

// StartTrustedDealerImport starts keygen using this party's dealer-provisioned
// constant term while preserving the ordinary keygen rounds and payloads.
func StartTrustedDealerImport(plan *TrustedDealerImportPlan, contribution *TrustedDealerContribution, local tss.LocalConfig, guard *tss.EnvelopeGuard) (*KeygenSession, []tss.Envelope, error) {
	if plan == nil || plan.state == nil {
		return nil, nil, invalidPlanConfig(local.Self, errors.New("nil trusted-dealer import plan"))
	}
	if err := plan.ValidateWithLimits(plan.limits); err != nil {
		return nil, nil, invalidPlanConfig(local.Self, err)
	}
	claimedScalar, claimedChainCode, err := contribution.beginClaimForPlan(plan, local.Self)
	if err != nil {
		return nil, nil, invalidPlanConfig(local.Self, err)
	}
	defer claimedScalar.Destroy()
	defer clear(claimedChainCode)
	committed := false
	defer func() {
		if !committed {
			contribution.rollbackClaim()
		}
	}()
	cfg, err := plan.thresholdConfig(local)
	if err != nil {
		return nil, nil, invalidPlanConfig(local.Self, err)
	}
	if err := cfg.ValidateWithLimits(plan.limits.ThresholdLimits()); err != nil {
		return nil, nil, invalidPlanConfig(local.Self, err)
	}
	if err := tss.RequireEnvelopeGuard(guard, tss.ProtocolFROSTEd25519, cfg.SessionID, cfg.Self); err != nil {
		return nil, nil, invalidPlanConfig(local.Self, err)
	}
	planHash, err := plan.Digest()
	if err != nil {
		return nil, nil, invalidPlanConfig(local.Self, err)
	}
	scalar, err := edScalarFromSecret(claimedScalar)
	if err != nil {
		return nil, nil, err
	}
	defer scalar.Set(fed.NewScalar())
	material, err := generateFROSTKeygenLocalMaterialWithContribution(cfg, scalar, claimedChainCode)
	if err != nil {
		return nil, nil, err
	}
	session, err := newFROSTKeygenSession(cfg, plan.limits, planHash, guard, material, plan)
	if err != nil {
		material.Destroy()
		return nil, nil, err
	}
	out, err := emitFROSTKeygenRound1(session, material)
	if err != nil {
		session.abort()
		return nil, nil, err
	}
	more, err := session.tryAdvance()
	if err != nil {
		clearEnvelopePayloads(out)
		session.abort()
		return nil, nil, err
	}
	out = append(out, more...)
	contribution.commitClaim()
	committed = true
	return session, out, nil
}

// GenerateTrustedDealerKeyShares runs the same trusted-dealer keygen state
// machines through a private authenticated in-memory router and returns one
// complete key share per party.
func GenerateTrustedDealerKeyShares(secretKey *SecretKey, option TrustedDealerImportOption, reader io.Reader) (*TrustedDealerImportPlan, map[tss.PartyID]*KeyShare, error) {
	if reader == nil {
		reader = rand.Reader
	}
	plan, contributions, err := NewTrustedDealerImport(secretKey, option, reader)
	if err != nil {
		return nil, nil, err
	}
	defer destroyFROSTContributions(contributions)
	security, err := inmemoryrun.New(plan.state.Parties, reader)
	if err != nil {
		return nil, nil, err
	}
	defer security.Destroy()
	sessions := make(map[tss.PartyID]*KeygenSession, len(plan.state.Parties))
	defer func() {
		for _, session := range sessions {
			session.Destroy()
		}
	}()
	queue := make([]tss.Envelope, 0, len(plan.state.Parties))
	for _, party := range plan.state.Parties {
		guard, err := security.Guard(party, plan.state.Parties, tss.ProtocolFROSTEd25519, plan.state.SessionID, FROSTPolicies())
		if err != nil {
			return nil, nil, err
		}
		signer, err := security.Signer(party)
		if err != nil {
			return nil, nil, err
		}
		session, out, err := StartTrustedDealerImport(plan, contributions[party], tss.LocalConfig{Self: party, Rand: reader, EnvelopeSigner: signer}, guard)
		if err != nil {
			return nil, nil, err
		}
		sessions[party] = session
		queue = append(queue, out...)
	}
	if err := security.Route(queue, plan.state.Parties, FROSTPolicies(), func(party tss.PartyID, inbound tss.InboundEnvelope) ([]tss.Envelope, error) {
		return sessions[party].Handle(inbound)
	}); err != nil {
		return nil, nil, err
	}
	shares := make(map[tss.PartyID]*KeyShare, len(plan.state.Parties))
	for _, party := range plan.state.Parties {
		share, ok := sessions[party].KeyShare()
		if !ok {
			for _, existing := range shares {
				existing.Destroy()
			}
			return nil, nil, fmt.Errorf("trusted-dealer keygen incomplete for party %d", party)
		}
		shares[party] = share
	}
	return cloneFROSTTrustedDealerPlan(plan), shares, nil
}

func splitFROSTDealerScalar(reader io.Reader, target *fed.Scalar, count int) ([]*fed.Scalar, error) {
	if count <= 0 {
		return nil, errors.New("empty trusted-dealer party set")
	}
	for {
		out := make([]*fed.Scalar, count)
		sum := fed.NewScalar()
		for i := 0; i < count-1; i++ {
			value, err := edcurve.RandomScalar(reader)
			if err != nil {
				clearScalars(out)
				sum.Set(fed.NewScalar())
				return nil, err
			}
			out[i] = value
			sum.Add(sum, value)
		}
		out[count-1] = fed.NewScalar().Subtract(target, sum)
		sum.Set(fed.NewScalar())
		if out[count-1].Equal(edcurve.ScalarZero()) == 0 {
			return out, nil
		}
		clearScalars(out)
	}
}

func splitDealerChainCode(reader io.Reader, target []byte, parties tss.PartySet) (map[tss.PartyID][]byte, error) {
	out := make(map[tss.PartyID][]byte, len(parties))
	remaining := bytes.Clone(target)
	for i, party := range parties {
		share := make([]byte, bip32util.ChainCodeSize)
		if i < len(parties)-1 {
			if _, err := io.ReadFull(reader, share); err != nil {
				clear(remaining)
				for _, value := range out {
					clear(value)
				}
				return nil, err
			}
			for j := range remaining {
				remaining[j] ^= share[j]
			}
		} else {
			copy(share, remaining)
		}
		out[party] = share
	}
	clear(remaining)
	return out, nil
}

func destroyFROSTContributions(contributions map[tss.PartyID]*TrustedDealerContribution) {
	for _, contribution := range contributions {
		contribution.Destroy()
	}
}

// SessionID returns the import session ID.
func (p *TrustedDealerImportPlan) SessionID() tss.SessionID {
	if p == nil || p.state == nil {
		return tss.SessionID{}
	}
	return p.state.SessionID
}

// Snapshot returns an independently owned public plan snapshot.
func (p *TrustedDealerImportPlan) Snapshot() (TrustedDealerImportPlanSnapshot, bool) {
	if p == nil || p.state == nil {
		return TrustedDealerImportPlanSnapshot{}, false
	}
	commitments := make(map[tss.PartyID][]byte, len(p.state.Commitments))
	for _, commitment := range p.state.Commitments {
		commitments[commitment.Party] = commitment.ConstantCommitment.Bytes()
	}
	return TrustedDealerImportPlanSnapshot{
		SessionID:   p.state.SessionID,
		Threshold:   p.state.Threshold,
		Parties:     p.state.Parties.Clone(),
		PublicKey:   p.state.PublicKey.Bytes(),
		ChainCode:   bytes.Clone(p.state.ChainCode),
		Commitments: commitments,
	}, true
}

// Digest returns the canonical trusted-dealer import intent digest.
func (p *TrustedDealerImportPlan) Digest() ([]byte, error) {
	if p == nil {
		return nil, errors.New("nil trusted-dealer import plan")
	}
	if err := p.ValidateWithLimits(p.limits); err != nil {
		return nil, err
	}
	t := transcript.New(trustedDealerImportPlanDigestLabel)
	t.AppendBytes("session_id", p.state.SessionID[:])
	t.AppendUint32("threshold", uint32(p.state.Threshold))
	t.AppendUint32List("parties", p.state.Parties)
	t.AppendBytes("public_key", p.state.PublicKey.Bytes())
	t.AppendBytes("chain_code", p.state.ChainCode)
	for _, commitment := range p.state.Commitments {
		t.AppendUint32("contribution_party", commitment.Party)
		t.AppendBytes("constant_commitment", commitment.ConstantCommitment.Bytes())
		t.AppendBytes("chain_code_commitment", commitment.ChainCodeCommit)
	}
	return t.Sum(), nil
}

// ValidateWithLimits validates the public import plan and contribution sum.
func (p *TrustedDealerImportPlan) ValidateWithLimits(limits Limits) error {
	if p == nil || p.state == nil {
		return errors.New("nil trusted-dealer import plan")
	}
	parties, err := validatePlanPartySetVerbose(p.state.Parties, p.state.Threshold, limits)
	if err != nil {
		return err
	}
	if !p.state.SessionID.Valid() {
		return tss.ErrInvalidSessionID
	}
	if err := p.state.PublicKey.Validate(); err != nil {
		return fmt.Errorf("invalid target public key: %w", err)
	}
	if len(p.state.ChainCode) != bip32util.ChainCodeSize {
		return fmt.Errorf("chain code must be %d bytes", bip32util.ChainCodeSize)
	}
	if len(p.state.Commitments) != len(parties) {
		return errors.New("trusted-dealer commitment count does not match party count")
	}
	points := make([]*fed.Point, 0, len(parties))
	for i, commitment := range p.state.Commitments {
		if commitment.Party != parties[i] {
			return errors.New("trusted-dealer commitments are not in canonical party order")
		}
		if err := commitment.ConstantCommitment.Validate(); err != nil {
			return fmt.Errorf("invalid contribution commitment for party %d: %w", commitment.Party, err)
		}
		if len(commitment.ChainCodeCommit) != sha256.Size {
			return fmt.Errorf("invalid chain-code commitment for party %d", commitment.Party)
		}
		points = append(points, commitment.ConstantCommitment.Point())
	}
	if !pointEqual(edcurve.AddPoints(points...), p.state.PublicKey.Point()) {
		return errors.New("trusted-dealer contribution commitments do not sum to target public key")
	}
	return nil
}

// Validate validates the public import plan with production limits.
func (p *TrustedDealerImportPlan) Validate() error {
	return p.ValidateWithLimits(DefaultLimits())
}

func (p *TrustedDealerImportPlan) commitmentFor(party tss.PartyID) (trustedDealerCommitment, bool) {
	if p == nil || p.state == nil {
		return trustedDealerCommitment{}, false
	}
	for _, commitment := range p.state.Commitments {
		if commitment.Party == party {
			return trustedDealerCommitment{
				Party:              commitment.Party,
				ConstantCommitment: commitment.ConstantCommitment.Clone(),
				ChainCodeCommit:    bytes.Clone(commitment.ChainCodeCommit),
			}, true
		}
	}
	return trustedDealerCommitment{}, false
}

func (p *TrustedDealerImportPlan) thresholdConfig(local tss.LocalConfig) (tss.ThresholdConfig, error) {
	if err := p.ValidateWithLimits(p.limits); err != nil {
		return tss.ThresholdConfig{}, err
	}
	if !tss.ContainsParty(p.state.Parties, local.Self) {
		return tss.ThresholdConfig{}, errors.New("local party is not in trusted-dealer import plan")
	}
	return tss.ThresholdConfig{
		Threshold:    p.state.Threshold,
		Parties:      p.state.Parties.Clone(),
		Self:         local.Self,
		SessionID:    p.state.SessionID,
		Rand:         local.Rand,
		Context:      local.Context,
		RoundTimeout: local.RoundTimeout,
		Log:          local.Log,
	}, nil
}

func cloneFROSTTrustedDealerPlan(p *TrustedDealerImportPlan) *TrustedDealerImportPlan {
	if p == nil || p.state == nil {
		return nil
	}
	commitments := make([]trustedDealerCommitment, len(p.state.Commitments))
	for i, commitment := range p.state.Commitments {
		commitments[i] = trustedDealerCommitment{
			Party:              commitment.Party,
			ConstantCommitment: commitment.ConstantCommitment.Clone(),
			ChainCodeCommit:    bytes.Clone(commitment.ChainCodeCommit),
		}
	}
	return &TrustedDealerImportPlan{state: &trustedDealerImportPlanState{
		SessionID:   p.state.SessionID,
		Threshold:   p.state.Threshold,
		Parties:     p.state.Parties.Clone(),
		PublicKey:   p.state.PublicKey.Clone(),
		ChainCode:   bytes.Clone(p.state.ChainCode),
		Commitments: commitments,
	}, limits: p.limits}
}

func (c *TrustedDealerContribution) validateForPlan(plan *TrustedDealerImportPlan, party tss.PartyID) error {
	if c == nil || c.state == nil || c.lifecycle == nil {
		return errors.New("nil trusted-dealer contribution")
	}
	c.lifecycle.mu.Lock()
	defer c.lifecycle.mu.Unlock()
	return c.validateForPlanLocked(plan, party)
}

func (c *TrustedDealerContribution) validateForPlanLocked(plan *TrustedDealerImportPlan, party tss.PartyID) error {
	if c.state == nil {
		return errors.New("nil trusted-dealer contribution")
	}
	if plan == nil || plan.state == nil {
		return errors.New("nil trusted-dealer import plan")
	}
	if c.state.Party != party || c.state.SessionID != plan.state.SessionID {
		return errors.New("trusted-dealer contribution identity mismatch")
	}
	planHash, err := plan.Digest()
	if err != nil {
		return err
	}
	if !bytes.Equal(c.state.PlanHash, planHash) {
		return errors.New("trusted-dealer contribution plan hash mismatch")
	}
	if len(c.state.ChainCode) != bip32util.ChainCodeSize {
		return errors.New("trusted-dealer contribution chain code must be 32 bytes")
	}
	scalar, err := edScalarFromSecret(c.state.Scalar)
	if err != nil {
		return err
	}
	defer scalar.Set(fed.NewScalar())
	if scalar.Equal(edcurve.ScalarZero()) == 1 {
		return errors.New("trusted-dealer contribution scalar is zero")
	}
	commitment, ok := plan.commitmentFor(party)
	if !ok {
		return errors.New("missing trusted-dealer commitment for local party")
	}
	if !pointEqual(fed.NewIdentityPoint().ScalarBaseMult(scalar), commitment.ConstantCommitment.Point()) {
		return errors.New("trusted-dealer contribution scalar does not match plan commitment")
	}
	wantChainCommit := bip32util.ChainCodeCommitment(frostChainCodeCommitLabel, c.state.SessionID, party, c.state.ChainCode)
	if !bytes.Equal(wantChainCommit, commitment.ChainCodeCommit) {
		return errors.New("trusted-dealer contribution chain code does not match plan commitment")
	}
	return nil
}

// PartyID returns the party bound to this contribution.
func (c *TrustedDealerContribution) PartyID() tss.PartyID {
	if c == nil || c.state == nil {
		return 0
	}
	return c.state.Party
}

// SessionID returns the import session bound to this contribution.
func (c *TrustedDealerContribution) SessionID() tss.SessionID {
	if c == nil || c.state == nil {
		return tss.SessionID{}
	}
	return c.state.SessionID
}

func (c *TrustedDealerContribution) beginClaimForPlan(plan *TrustedDealerImportPlan, party tss.PartyID) (*secret.Scalar, []byte, error) {
	if c == nil || c.lifecycle == nil {
		return nil, nil, errors.New("nil trusted-dealer contribution")
	}
	c.lifecycle.mu.Lock()
	defer c.lifecycle.mu.Unlock()
	if c.lifecycle.status != 0 {
		return nil, nil, errors.New("trusted-dealer contribution already claimed or consumed")
	}
	if err := c.validateForPlanLocked(plan, party); err != nil {
		return nil, nil, err
	}
	c.lifecycle.status = 1
	return c.state.Scalar.Clone(), bytes.Clone(c.state.ChainCode), nil
}

func (c *TrustedDealerContribution) rollbackClaim() {
	c.lifecycle.mu.Lock()
	defer c.lifecycle.mu.Unlock()
	if c.lifecycle.status == 1 {
		c.lifecycle.status = 0
	}
}

func (c *TrustedDealerContribution) commitClaim() {
	c.lifecycle.mu.Lock()
	defer c.lifecycle.mu.Unlock()
	if c.lifecycle.status == 1 {
		c.lifecycle.status = 2
		c.state.Scalar.Destroy()
		clear(c.state.ChainCode)
	}
}

// Destroy clears the contribution and permanently prevents its use.
func (c *TrustedDealerContribution) Destroy() {
	if c == nil || c.lifecycle == nil {
		return
	}
	c.lifecycle.mu.Lock()
	defer c.lifecycle.mu.Unlock()
	c.lifecycle.status = 2
	if c.state != nil {
		if c.state.Scalar != nil {
			c.state.Scalar.Destroy()
		}
		clear(c.state.ChainCode)
	}
}

// MarshalJSON rejects JSON encoding of secret contributions.
func (c TrustedDealerContribution) MarshalJSON() ([]byte, error) {
	return nil, errors.New("trusted-dealer contribution must not be JSON-encoded")
}

// String returns a redacted contribution representation.
func (c TrustedDealerContribution) String() string {
	party := tss.PartyID(0)
	if c.state != nil {
		party = c.state.Party
	}
	return fmt.Sprintf("TrustedDealerContribution{Party:%d Secret:<redacted>}", party)
}

// GoString returns a redacted contribution representation.
func (c TrustedDealerContribution) GoString() string { return c.String() }

// Format writes a redacted representation for every formatting verb.
func (c TrustedDealerContribution) Format(state fmt.State, verb rune) {
	_, _ = fmt.Fprint(state, c.String())
}

// MarshalBinary returns the canonical public import-plan encoding.
func (p *TrustedDealerImportPlan) MarshalBinary() ([]byte, error) {
	if p == nil {
		return nil, errors.New("nil trusted-dealer import plan")
	}
	return p.MarshalBinaryWithLimits(p.limits)
}

// MarshalBinaryWithLimits returns the canonical public import-plan encoding.
func (p *TrustedDealerImportPlan) MarshalBinaryWithLimits(limits Limits) ([]byte, error) {
	if err := p.ValidateWithLimits(limits); err != nil {
		return nil, err
	}
	raw, err := wire.Marshal(p.state, wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
	if err != nil {
		return nil, err
	}
	if len(raw) > limits.State.MaxSerializedTrustedDealerPlanBytes {
		return nil, errors.New("trusted-dealer import plan exceeds size limit")
	}
	return raw, nil
}

// UnmarshalBinary decodes a canonical public import plan.
func (p *TrustedDealerImportPlan) UnmarshalBinary(in []byte) error {
	return p.UnmarshalBinaryWithLimits(in, DefaultLimits())
}

// UnmarshalBinaryWithLimits decodes a canonical public import plan with limits.
func (p *TrustedDealerImportPlan) UnmarshalBinaryWithLimits(in []byte, limits Limits) error {
	if p == nil {
		return errors.New("nil trusted-dealer import plan receiver")
	}
	if len(in) > limits.State.MaxSerializedTrustedDealerPlanBytes {
		return errors.New("trusted-dealer import plan exceeds size limit")
	}
	var state trustedDealerImportPlanState
	if err := wire.Unmarshal(in, &state,
		wire.WithFrameLimits(limits.frameLimits(limits.State.MaxSerializedTrustedDealerPlanBytes)),
		wire.WithFieldLimits(limits.fieldLimits()),
	); err != nil {
		return err
	}
	decoded := &TrustedDealerImportPlan{state: &state, limits: limits}
	if err := decoded.ValidateWithLimits(limits); err != nil {
		return err
	}
	*p = *decoded
	return nil
}

// MarshalBinary returns the canonical secret contribution encoding.
func (c *TrustedDealerContribution) MarshalBinary() ([]byte, error) {
	return c.MarshalBinaryWithLimits(DefaultLimits())
}

// MarshalBinaryWithLimits returns the canonical secret contribution encoding.
func (c *TrustedDealerContribution) MarshalBinaryWithLimits(limits Limits) ([]byte, error) {
	if c == nil || c.state == nil || c.lifecycle == nil {
		return nil, errors.New("nil trusted-dealer contribution")
	}
	c.lifecycle.mu.Lock()
	defer c.lifecycle.mu.Unlock()
	if c.lifecycle.status != 0 {
		return nil, errors.New("trusted-dealer contribution is claimed or consumed")
	}
	if !c.state.SessionID.Valid() || c.state.Party == 0 || len(c.state.PlanHash) != sha256.Size || len(c.state.ChainCode) != bip32util.ChainCodeSize || validateFROSTDealerScalar(c.state.Scalar) != nil {
		return nil, errors.New("invalid trusted-dealer contribution")
	}
	raw, err := wire.Marshal(c.state, wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
	if err != nil {
		return nil, err
	}
	if len(raw) > limits.State.MaxSerializedTrustedDealerContributionBytes {
		return nil, errors.New("trusted-dealer contribution exceeds size limit")
	}
	return raw, nil
}

// UnmarshalBinary decodes a canonical secret contribution.
func (c *TrustedDealerContribution) UnmarshalBinary(in []byte) error {
	return c.UnmarshalBinaryWithLimits(in, DefaultLimits())
}

// UnmarshalBinaryWithLimits decodes a canonical secret contribution with limits.
func (c *TrustedDealerContribution) UnmarshalBinaryWithLimits(in []byte, limits Limits) error {
	if c == nil {
		return errors.New("nil trusted-dealer contribution receiver")
	}
	if len(in) > limits.State.MaxSerializedTrustedDealerContributionBytes {
		return errors.New("trusted-dealer contribution exceeds size limit")
	}
	var state trustedDealerContributionState
	if err := wire.Unmarshal(in, &state,
		wire.WithFrameLimits(limits.frameLimits(limits.State.MaxSerializedTrustedDealerContributionBytes)),
		wire.WithFieldLimits(limits.fieldLimits()),
	); err != nil {
		if state.Scalar != nil {
			state.Scalar.Destroy()
		}
		clear(state.ChainCode)
		return err
	}
	if !state.SessionID.Valid() || state.Party == 0 || len(state.PlanHash) != sha256.Size || len(state.ChainCode) != bip32util.ChainCodeSize || validateFROSTDealerScalar(state.Scalar) != nil {
		if state.Scalar != nil {
			state.Scalar.Destroy()
		}
		clear(state.ChainCode)
		return errors.New("invalid trusted-dealer contribution")
	}
	c.Destroy()
	*c = TrustedDealerContribution{state: &state, lifecycle: new(contributionLifecycle)}
	return nil
}

// WireType returns the canonical wire type for trusted-dealer plans.
func (*trustedDealerImportPlanState) WireType() string { return trustedDealerImportPlanWireType }

// WireVersion returns the trusted-dealer plan wire version.
func (*trustedDealerImportPlanState) WireVersion() uint16 { return trustedDealerImportPlanWireVersion }

// WireType returns the canonical wire type for trusted-dealer contributions.
func (*trustedDealerContributionState) WireType() string { return trustedDealerContributionWireType }

// WireVersion returns the trusted-dealer contribution wire version.
func (*trustedDealerContributionState) WireVersion() uint16 {
	return trustedDealerContributionWireVersion
}

func validateFROSTDealerScalar(value *secret.Scalar) error {
	scalar, err := edScalarFromSecret(value)
	if err != nil {
		return err
	}
	defer scalar.Set(fed.NewScalar())
	if scalar.Equal(edcurve.ScalarZero()) == 1 {
		return errors.New("trusted-dealer contribution scalar is zero")
	}
	return nil
}
