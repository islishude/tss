package ed25519

import (
	"testing"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
)

func TestSemanticCommitmentIdentityPolicies(t *testing.T) {
	t.Parallel()
	generator := fed.NewGeneratorPoint()
	identity := fed.NewIdentityPoint()

	if _, err := newKeygenCommitmentsFromPoints([]*fed.Point{identity, generator}, 2); err == nil {
		t.Fatal("keygen commitments accepted identity constant term")
	}
	if _, err := newKeygenCommitmentsFromPoints([]*fed.Point{generator, identity}, 2); err != nil {
		t.Fatalf("keygen commitments rejected identity higher coefficient: %v", err)
	}
	if _, err := newReshareCommitmentsFromPoints([]*fed.Point{identity, identity}, 2); err != nil {
		t.Fatalf("reshare commitments rejected identity: %v", err)
	}
	if _, err := newGroupCommitmentsFromPoints([]*fed.Point{identity, generator}, 2); err == nil {
		t.Fatal("group commitments accepted identity public key")
	}
}

func TestSemanticCommitmentEvaluationMatchesCurveHelper(t *testing.T) {
	t.Parallel()
	points := []*fed.Point{
		fed.NewGeneratorPoint(),
		fed.NewIdentityPoint().ScalarBaseMult(edcurve.ScalarFromUint64(7)),
	}
	group, err := newGroupCommitmentsFromPoints(points, len(points))
	if err != nil {
		t.Fatal(err)
	}
	got, err := group.Eval(tss.PartyID(3))
	if err != nil {
		t.Fatal(err)
	}
	want, err := edcurve.EvalCommitments(group.BytesList(), 3)
	if err != nil {
		t.Fatal(err)
	}
	wantPoint, err := newVerificationSharePointFromBytes(want)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(wantPoint) {
		t.Fatal("semantic commitment evaluation mismatch")
	}
}

func TestSemanticCommitmentBytesAreOwned(t *testing.T) {
	t.Parallel()
	group, err := newGroupCommitmentsFromPoints([]*fed.Point{fed.NewGeneratorPoint()}, 1)
	if err != nil {
		t.Fatal(err)
	}
	first := group.BytesList()
	first[0][0] ^= 1
	second := group.BytesList()
	if first[0][0] == second[0][0] {
		t.Fatal("BytesList exposed mutable internal state")
	}
	clone := group.Clone()
	if !group.Equal(clone) {
		t.Fatal("group commitment clone mismatch")
	}
}
