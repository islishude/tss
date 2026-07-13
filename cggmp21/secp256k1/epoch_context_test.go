package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/testutil"
	"github.com/islishude/tss/internal/wire"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

func TestCGGMP21EpochContextCanonicalRoundTripAndDefensiveCopies(t *testing.T) {
	t.Parallel()

	source := bytes.Repeat([]byte{0xa5}, sha256.Size)
	ctx, state := epochTestFixture(t, source)
	raw, err := ctx.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	rawAgain, err := ctx.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, rawAgain) {
		t.Fatal("epoch context encoding is not deterministic")
	}

	var decoded EpochContext
	if err := decoded.UnmarshalBinaryWithLimits(raw, testLimits()); err != nil {
		t.Fatal(err)
	}
	reencoded, err := decoded.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, reencoded) {
		t.Fatal("epoch context changed across canonical round trip")
	}

	identifier, ok := ctx.Identifier(ctx.Identifiers[0].Party)
	if !ok {
		t.Fatal("missing epoch identifier")
	}
	identifier[0] ^= 0xff
	identifierAgain, ok := ctx.Identifier(ctx.Identifiers[0].Party)
	if !ok || bytes.Equal(identifier, identifierAgain) {
		t.Fatal("epoch identifier accessor aliases internal state")
	}
	publicShare, ok := ctx.PublicShare(ctx.PublicShares[0].Party)
	if !ok {
		t.Fatal("missing epoch public share")
	}
	publicShare.PublicKey[0] ^= 0xff
	publicShareAgain, ok := ctx.PublicShare(ctx.PublicShares[0].Party)
	if !ok || bytes.Equal(publicShare.PublicKey, publicShareAgain.PublicKey) {
		t.Fatal("epoch public-share accessor aliases internal state")
	}
	sourceBytes, ok := ctx.SourceEpochIDBytes()
	if !ok {
		t.Fatal("missing source epoch id")
	}
	sourceBytes[0] ^= 0xff
	sourceAgain, ok := ctx.SourceEpochIDBytes()
	if !ok || bytes.Equal(sourceBytes, sourceAgain) {
		t.Fatal("source epoch id accessor aliases internal state")
	}

	clone := ctx.Clone()
	clone.EpochID[0] ^= 0xff
	clone.Identifiers[0].Identifier[0] ^= 0xff
	clone.PublicShares[0].PublicKey[0] ^= 0xff
	clone.AuxiliaryDigest[0] ^= 0xff
	clone.SourceEpochID[0] ^= 0xff
	if bytes.Equal(clone.EpochID, ctx.EpochID) ||
		bytes.Equal(clone.Identifiers[0].Identifier, ctx.Identifiers[0].Identifier) ||
		bytes.Equal(clone.PublicShares[0].PublicKey, ctx.PublicShares[0].PublicKey) ||
		bytes.Equal(clone.AuxiliaryDigest, ctx.AuxiliaryDigest) ||
		*clone.SourceEpochID == *ctx.SourceEpochID {
		t.Fatal("epoch context clone aliases source state")
	}

	share := &KeyShare{state: state}
	keyEpoch, ok := share.EpochContext()
	if !ok {
		t.Fatal("key share did not expose its valid epoch context")
	}
	keyEpoch.EpochID[0] ^= 0xff
	keyEpochAgain, ok := share.EpochContext()
	if !ok || bytes.Equal(keyEpoch.EpochID, keyEpochAgain.EpochID) {
		t.Fatal("key-share epoch accessor aliases internal state")
	}
	metadataClone := (KeySharePublicMetadata{Epoch: ctx}).Clone()
	metadataClone.Epoch.EpochID[0] ^= 0xff
	if bytes.Equal(metadataClone.Epoch.EpochID, ctx.EpochID) {
		t.Fatal("key-share public metadata clone aliases epoch state")
	}
}

func TestCGGMP21EpochContextRejectsBoundFieldMutation(t *testing.T) {
	t.Parallel()

	base, _ := epochTestFixture(t, nil)
	validPoint := mustEpochPointBytes(t, 99)
	mutations := []struct {
		name   string
		mutate func(*EpochContext)
	}{
		{name: "sid", mutate: func(e *EpochContext) { e.SID[0] ^= 0xff }},
		{name: "rid", mutate: func(e *EpochContext) { e.RID[0] ^= 0xff }},
		{name: "threshold", mutate: func(e *EpochContext) { e.Threshold++ }},
		{name: "epoch id", mutate: func(e *EpochContext) { e.EpochID[0] ^= 0xff }},
		{name: "zero epoch id", mutate: func(e *EpochContext) { e.EpochID = make([]byte, sha256.Size) }},
		{name: "identifier", mutate: func(e *EpochContext) { e.Identifiers[0].Identifier = secp.ScalarFromUint64(7).Bytes() }},
		{name: "public share", mutate: func(e *EpochContext) { e.PublicShares[0].PublicKey = bytes.Clone(validPoint) }},
		{name: "auxiliary digest", mutate: func(e *EpochContext) { e.AuxiliaryDigest[0] ^= 0xff }},
		{name: "source epoch", mutate: func(e *EpochContext) {
			source, err := newEpochSourceID(bytes.Repeat([]byte{0x44}, sha256.Size))
			if err != nil {
				panic(err)
			}
			e.SourceEpochID = source
		}},
		{name: "party order", mutate: func(e *EpochContext) {
			e.Identifiers[0], e.Identifiers[1] = e.Identifiers[1], e.Identifiers[0]
		}},
	}
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			mutated := base.Clone()
			tc.mutate(mutated)
			if err := mutated.ValidateWithLimits(testLimits()); err == nil {
				t.Fatal("mutated epoch context validated")
			}
		})
	}
}

func TestCGGMP21EpochContextRejectsIdentifierCollision(t *testing.T) {
	t.Parallel()

	ctx, _ := epochTestFixture(t, nil)
	ctx.Identifiers[1].Identifier = bytes.Clone(ctx.Identifiers[0].Identifier)
	ctx.EpochID = ctx.computeID()
	err := ctx.ValidateWithLimits(testLimits())
	if err == nil || !strings.Contains(err.Error(), "duplicate Shamir identifier") {
		t.Fatalf("identifier collision error = %v", err)
	}
}

func TestCGGMP21EpochIdentifierSamplerBoundaries(t *testing.T) {
	t.Parallel()

	zeroCalls := 0
	if _, err := deriveEpochIdentifierWithDigest(func(uint32) []byte {
		zeroCalls++
		return make([]byte, sha256.Size)
	}); !errors.Is(err, errEpochIdentifierZero) {
		t.Fatalf("zero candidate error = %v, want terminal zero error", err)
	}
	if zeroCalls != 1 {
		t.Fatalf("zero candidate retried %d times, want one terminal attempt", zeroCalls)
	}

	q := secp.Order().FillBytes(make([]byte, sha256.Size))
	qMinusOne := new(big.Int).Sub(secp.Order(), big.NewInt(1)).FillBytes(make([]byte, sha256.Size))
	accepted, err := deriveEpochIdentifierWithDigest(func(uint32) []byte {
		return bytes.Clone(qMinusOne)
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(accepted, qMinusOne) {
		t.Fatal("q-1 candidate changed its canonical representative")
	}

	retryCalls := 0
	accepted, err = deriveEpochIdentifierWithDigest(func(uint32) []byte {
		retryCalls++
		if retryCalls == 1 {
			return bytes.Clone(q)
		}
		return bytes.Clone(qMinusOne)
	})
	if err != nil {
		t.Fatal(err)
	}
	if retryCalls != 2 || !bytes.Equal(accepted, qMinusOne) {
		t.Fatal("non-canonical candidate was not retried deterministically")
	}

	exhaustionCalls := 0
	if _, err := deriveEpochIdentifierWithDigest(func(uint32) []byte {
		exhaustionCalls++
		return bytes.Clone(q)
	}); !errors.Is(err, errEpochIdentifierExhausted) {
		t.Fatalf("q exhaustion error = %v, want bounded exhaustion", err)
	}
	if exhaustionCalls != maxEpochIdentifierCandidates {
		t.Fatalf("sampler attempts = %d, want %d", exhaustionCalls, maxEpochIdentifierCandidates)
	}
}

func TestCGGMP21EpochContextThresholdAndKeyShareBindings(t *testing.T) {
	t.Parallel()

	ctx, state := epochTestFixture(t, nil)
	before, err := ctx.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err := state.validateEpochBinding(testLimits()); err != nil {
		t.Fatal(err)
	}
	after, err := ctx.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("epoch validation mutated accepted state")
	}

	for _, threshold := range []int{0, len(ctx.Identifiers) + 1} {
		mutated := ctx.Clone()
		mutated.Threshold = threshold
		mutated.EpochID = mutated.computeID()
		if err := mutated.ValidateWithLimits(testLimits()); err == nil {
			t.Fatalf("epoch context accepted threshold %d", threshold)
		}
	}

	wrongThreshold := ctx.Clone()
	wrongThreshold.Threshold++
	wrongThreshold.EpochID = wrongThreshold.computeID()
	if err := wrongThreshold.ValidateWithLimits(testLimits()); err != nil {
		t.Fatal(err)
	}
	state.Epoch = wrongThreshold
	if err := state.validateEpochBinding(testLimits()); err == nil {
		t.Fatal("key share accepted an epoch with a different threshold")
	}

	_, refreshedRun := epochTestFixture(t, nil)
	refreshedRun.PaillierProofSessionID = epochTestSession(0xa7)
	if refreshedRun.PaillierProofSessionID == refreshedRun.Epoch.SID {
		t.Fatal("test fixture did not separate stable SID from run session")
	}
	if err := refreshedRun.validateEpochBinding(testLimits()); err != nil {
		t.Fatalf("key share rejected a fresh auxiliary run under the stable SID: %v", err)
	}

	_, missingRun := epochTestFixture(t, nil)
	missingRun.PaillierProofSessionID = tss.SessionID{}
	if err := missingRun.validateEpochBinding(testLimits()); err == nil {
		t.Fatal("key share accepted a missing auxiliary proof run session")
	}

	_, wrongAuxiliary := epochTestFixture(t, nil)
	data := wrongAuxiliary.PartyData[wrongAuxiliary.Parties[0]]
	data.PaillierPublicKey = epochTestPaillierPublicKey(85)
	wrongAuxiliary.PartyData[wrongAuxiliary.Parties[0]] = data
	if err := wrongAuxiliary.validateEpochBinding(testLimits()); err == nil {
		t.Fatal("key share accepted an epoch bound to different auxiliary material")
	}

	_, wrongPublicShare := epochTestFixture(t, nil)
	data = wrongPublicShare.PartyData[wrongPublicShare.Parties[0]]
	data.VerificationShare = mustEpochPointBytes(t, 101)
	wrongPublicShare.PartyData[wrongPublicShare.Parties[0]] = data
	if err := wrongPublicShare.validateEpochBinding(testLimits()); err == nil {
		t.Fatal("key share accepted an epoch bound to a different public-share vector")
	}

	_, missing := epochTestFixture(t, nil)
	missing.Epoch = nil
	if err := missing.validateEpochBinding(testLimits()); err == nil {
		t.Fatal("key share accepted missing epoch context")
	}
}

func TestCGGMP21EpochContextSourceEpochWireIsOptionalExactWidth(t *testing.T) {
	t.Parallel()

	withoutSource, _ := epochTestFixture(t, nil)
	raw, err := withoutSource.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	_, fields, err := wire.UnmarshalFields(raw, epochContextWireType)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range fields {
		if field.Tag == 8 {
			t.Fatal("absent source epoch id was encoded as a present empty field")
		}
	}

	withSource, _ := epochTestFixture(t, bytes.Repeat([]byte{0x65}, sha256.Size))
	raw, err = withSource.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	short, err := testutil.RewriteWireField(raw, epochContextWireType, 8, make([]byte, sha256.Size-1))
	if err != nil {
		t.Fatal(err)
	}
	var decoded EpochContext
	if err := decoded.UnmarshalBinaryWithLimits(short, testLimits()); err == nil {
		t.Fatal("epoch context accepted a short optional source epoch id")
	}
	if _, err := NewEpochContext(EpochContextOption{
		SID:             withSource.SID,
		RID:             withSource.RID,
		Threshold:       withSource.Threshold,
		Parties:         epochParties(withSource),
		PublicShares:    cloneEpochPublicShares(withSource.PublicShares),
		AuxiliaryDigest: bytes.Clone(withSource.AuxiliaryDigest),
		SourceEpochID:   make([]byte, sha256.Size-1),
	}); err == nil {
		t.Fatal("epoch constructor accepted a short source epoch id")
	}
	if _, err := NewEpochContext(EpochContextOption{
		SID:             withSource.SID,
		RID:             withSource.RID,
		Threshold:       withSource.Threshold,
		Parties:         epochParties(withSource),
		PublicShares:    cloneEpochPublicShares(withSource.PublicShares),
		AuxiliaryDigest: bytes.Clone(withSource.AuxiliaryDigest),
		SourceEpochID:   make([]byte, sha256.Size),
	}); err == nil {
		t.Fatal("epoch constructor accepted a zero source epoch id")
	}
}

func epochTestFixture(t testing.TB, sourceEpochID []byte) (*EpochContext, *keyShareState) {
	t.Helper()

	parties := tss.NewPartySet(1, 4, 9)
	sid := epochTestSession(0x31)
	rid := epochTestSession(0x72)
	commitments := []*secp.Point{
		secp.ScalarBaseMult(secp.ScalarFromUint64(42)),
		secp.ScalarBaseMult(secp.ScalarFromUint64(9)),
	}
	paillierModuli := []int64{65, 77, 85}
	ringPedersenModuli := []int64{77, 85, 65}
	partyData := make(map[tss.PartyID]keySharePartyData, len(parties))
	publicShares := make([]EpochPublicShare, len(parties))
	for i, party := range parties {
		identifier, err := DeriveEpochIdentifier(sid, rid, party)
		if err != nil {
			t.Fatal(err)
		}
		point, err := evaluateCommitmentPointsAtIdentifier(commitments, identifier)
		if err != nil {
			t.Fatal(err)
		}
		publicKey, err := secp.PointBytes(point)
		if err != nil {
			t.Fatal(err)
		}
		publicShares[i] = EpochPublicShare{Party: party, PublicKey: publicKey}
		partyData[party] = keySharePartyData{
			VerificationShare:  bytes.Clone(publicKey),
			PaillierPublicKey:  epochTestPaillierPublicKey(paillierModuli[i]),
			RingPedersenParams: epochTestRingPedersenParams(ringPedersenModuli[i]),
		}
	}
	auxiliaryDigest, err := computeEpochAuxiliaryDigest(parties, partyData)
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := NewEpochContext(EpochContextOption{
		SID:             sid,
		RID:             rid,
		Threshold:       len(commitments),
		Parties:         parties,
		PublicShares:    publicShares,
		AuxiliaryDigest: auxiliaryDigest,
		SourceEpochID:   sourceEpochID,
	})
	if err != nil {
		t.Fatal(err)
	}
	state := &keyShareState{
		Party:                  parties[0],
		Threshold:              len(commitments),
		Parties:                parties.Clone(),
		GroupCommitments:       commitments,
		PartyData:              partyData,
		PaillierProofSessionID: sid,
		Epoch:                  ctx.Clone(),
	}
	return ctx, state
}

func epochTestSession(fill byte) tss.SessionID {
	var out tss.SessionID
	for i := range out {
		out[i] = fill
	}
	return out
}

func epochTestPaillierPublicKey(modulus int64) *pai.PublicKey {
	n := big.NewInt(modulus)
	return &pai.PublicKey{
		N:        n,
		G:        new(big.Int).Add(n, big.NewInt(1)),
		NSquared: new(big.Int).Mul(n, n),
	}
}

func epochTestRingPedersenParams(modulus int64) *zkpai.RingPedersenParams {
	return &zkpai.RingPedersenParams{
		N: big.NewInt(modulus),
		S: big.NewInt(4),
		T: big.NewInt(9),
	}
}

func mustEpochPointBytes(t testing.TB, scalar uint64) []byte {
	t.Helper()
	out, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromUint64(scalar)))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func epochParties(ctx *EpochContext) tss.PartySet {
	parties := make(tss.PartySet, len(ctx.Identifiers))
	for i := range ctx.Identifiers {
		parties[i] = ctx.Identifiers[i].Party
	}
	return parties
}

func cloneEpochPublicShares(in []EpochPublicShare) []EpochPublicShare {
	out := make([]EpochPublicShare, len(in))
	for i := range in {
		out[i] = in[i].Clone()
	}
	return out
}
