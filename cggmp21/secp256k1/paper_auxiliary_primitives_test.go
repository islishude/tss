package secp256k1

import (
	"bytes"
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/shamir"
	"github.com/islishude/tss/internal/testutil"
	"github.com/islishude/tss/internal/zk/schnorr"
)

func TestFigureCoinXORRejectsZeroAndMissingContribution(t *testing.T) {
	parties := tss.NewPartySet(1, 2)
	left := bytes.Repeat([]byte{0x5a}, 32)
	right := bytes.Repeat([]byte{0xa5}, 32)
	rid, err := xorFigureCoins(parties, map[tss.PartyID][]byte{1: left, 2: right}, "rid")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rid[:], bytes.Repeat([]byte{0xff}, 32)) {
		t.Fatalf("rid = %x", rid)
	}
	if _, err := xorFigureCoins(parties, map[tss.PartyID][]byte{1: left}, "rid"); err == nil {
		t.Fatal("missing contribution accepted")
	}
	if _, err := xorFigureCoins(parties, map[tss.PartyID][]byte{1: left, 2: bytes.Clone(left)}, "rid"); err == nil {
		t.Fatal("zero XOR result accepted")
	}
}

func TestFigure7DHMaskIsSymmetricAndEpochBound(t *testing.T) {
	scalar1, err := secp.RandomScalar(testutil.DeterministicReader(1801))
	if err != nil {
		t.Fatal(err)
	}
	scalar2, err := secp.RandomScalar(testutil.DeterministicReader(1802))
	if err != nil {
		t.Fatal(err)
	}
	secret1, err := secpSecretScalarFromScalar(scalar1)
	if err != nil {
		t.Fatal(err)
	}
	defer secret1.Destroy()
	secret2, err := secpSecretScalarFromScalar(scalar2)
	if err != nil {
		t.Fatal(err)
	}
	defer secret2.Destroy()
	public1, err := secp.PointBytes(secp.ScalarBaseMult(scalar1))
	if err != nil {
		t.Fatal(err)
	}
	public2, err := secp.PointBytes(secp.ScalarBaseMult(scalar2))
	if err != nil {
		t.Fatal(err)
	}
	shared12, err := figure7DHSharedSecret(public2, secret1)
	if err != nil {
		t.Fatal(err)
	}
	shared21, err := figure7DHSharedSecret(public1, secret2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(shared12, shared21) {
		t.Fatal("DH shared points differ")
	}
	sid := tss.SessionID(bytes.Repeat([]byte{0x11}, 32))
	runSessionID := tss.SessionID(bytes.Repeat([]byte{0x12}, 32))
	rid := tss.SessionID(bytes.Repeat([]byte{0x22}, 32))
	epochID := bytes.Repeat([]byte{0x24}, 32)
	planHash := bytes.Repeat([]byte{0x33}, 32)
	mask12, err := deriveFigure7DHMask(sid, runSessionID, rid, epochID, 1, 2, shared12, planHash)
	if err != nil {
		t.Fatal(err)
	}
	mask21, err := deriveFigure7DHMask(sid, runSessionID, rid, epochID, 1, 2, shared21, planHash)
	if err != nil {
		t.Fatal(err)
	}
	if !mask12.Equal(mask21) {
		t.Fatal("DH masks differ")
	}
	share := secp.ScalarFromUint64(41)
	masked := maskFigure7Share(share, mask12)
	unmasked, err := unmaskFigure7Share(masked, mask21)
	if err != nil {
		t.Fatal(err)
	}
	if !unmasked.Equal(share) {
		t.Fatal("DH mask round trip changed share")
	}
	wrongRID := rid
	wrongRID[0] ^= 1
	wrongMask, err := deriveFigure7DHMask(sid, runSessionID, wrongRID, epochID, 1, 2, shared21, planHash)
	if err != nil {
		t.Fatal(err)
	}
	wrongShare, err := unmaskFigure7Share(masked, wrongMask)
	if err != nil {
		t.Fatal(err)
	}
	if wrongShare.Equal(share) {
		t.Fatal("wrong epoch RID recovered the share")
	}
	wrongEpochID := bytes.Clone(epochID)
	wrongEpochID[0] ^= 1
	wrongEpochMask, err := deriveFigure7DHMask(sid, runSessionID, rid, wrongEpochID, 1, 2, shared21, planHash)
	if err != nil {
		t.Fatal(err)
	}
	wrongEpochShare, err := unmaskFigure7Share(masked, wrongEpochMask)
	if err != nil {
		t.Fatal(err)
	}
	if wrongEpochShare.Equal(share) {
		t.Fatal("mutated epoch ID recovered the share")
	}
}

func TestFigure7ProofDomainRejectsMutatedEpochID(t *testing.T) {
	sid := tss.SessionID(bytes.Repeat([]byte{0x61}, 32))
	runSessionID := tss.SessionID(bytes.Repeat([]byte{0x65}, 32))
	rid := tss.SessionID(bytes.Repeat([]byte{0x62}, 32))
	epochID := bytes.Repeat([]byte{0x63}, 32)
	planHash := bytes.Repeat([]byte{0x64}, 32)
	parties := tss.NewPartySet(1, 2)
	domain, err := figure7SchnorrDomain(sid, runSessionID, rid, epochID, parties, 2, 1, 0, planHash)
	if err != nil {
		t.Fatal(err)
	}
	value := secp.ScalarFromUint64(19)
	witness, err := secpSecretScalarFromScalar(value)
	if err != nil {
		t.Fatal(err)
	}
	defer witness.Destroy()
	proof, public, err := schnorr.Prove(domain, witness)
	if err != nil {
		t.Fatal(err)
	}
	mutatedEpochID := bytes.Clone(epochID)
	mutatedEpochID[0] ^= 1
	mutatedDomain, err := figure7SchnorrDomain(sid, runSessionID, rid, mutatedEpochID, parties, 2, 1, 0, planHash)
	if err != nil {
		t.Fatal(err)
	}
	if schnorr.Verify(mutatedDomain, public, proof) {
		t.Fatal("Figure 7 Schnorr proof verified after changing only EpochID")
	}
	mutatedStableSID := sid
	mutatedStableSID[0] ^= 1
	mutatedDomain, err = figure7SchnorrDomain(mutatedStableSID, runSessionID, rid, epochID, parties, 2, 1, 0, planHash)
	if err != nil {
		t.Fatal(err)
	}
	if schnorr.Verify(mutatedDomain, public, proof) {
		t.Fatal("Figure 7 Schnorr proof verified after changing only stable SID")
	}
	mutatedRunSessionID := runSessionID
	mutatedRunSessionID[0] ^= 1
	mutatedDomain, err = figure7SchnorrDomain(sid, mutatedRunSessionID, rid, epochID, parties, 2, 1, 0, planHash)
	if err != nil {
		t.Fatal(err)
	}
	if schnorr.Verify(mutatedDomain, public, proof) {
		t.Fatal("Figure 7 Schnorr proof verified after changing only run session")
	}
}

func TestFigure7DynamicIdentifierPolynomialVerification(t *testing.T) {
	sid := tss.SessionID(bytes.Repeat([]byte{0x41}, 32))
	rid := tss.SessionID(bytes.Repeat([]byte{0x42}, 32))
	wrongRID := tss.SessionID(bytes.Repeat([]byte{0x43}, 32))
	id, err := DeriveEpochIdentifier(sid, rid, 2)
	if err != nil {
		t.Fatal(err)
	}
	wrongID, err := DeriveEpochIdentifier(sid, wrongRID, 2)
	if err != nil {
		t.Fatal(err)
	}
	epoch := &EpochContext{Identifiers: []EpochPartyIdentifier{{Party: 2, Identifier: id}}}
	poly := shamir.Polynomial{secp.ScalarFromUint64(7), secp.ScalarFromUint64(13)}
	share, err := evaluateFigure7Polynomial(poly, epoch, 2)
	if err != nil {
		t.Fatal(err)
	}
	commitments := make([][]byte, len(poly))
	for i, coefficient := range poly {
		commitments[i], err = secp.PointBytes(secp.ScalarBaseMult(coefficient))
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := verifyFigure7Share(commitments, id, share.Bytes()); err != nil {
		t.Fatalf("valid dynamic share rejected: %v", err)
	}
	if err := verifyFigure7Share(commitments, wrongID, share.Bytes()); err == nil {
		t.Fatal("wrong-epoch identifier accepted")
	}
}

func TestFigure6CommitmentBindsEveryOpening(t *testing.T) {
	sid := tss.SessionID(bytes.Repeat([]byte{0x51}, 32))
	rho := bytes.Repeat([]byte{0x52}, 32)
	decommitment := bytes.Repeat([]byte{0x53}, 32)
	planHash := bytes.Repeat([]byte{0x54}, 32)
	public, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromUint64(5)))
	if err != nil {
		t.Fatal(err)
	}
	schnorrCommitment, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromUint64(6)))
	if err != nil {
		t.Fatal(err)
	}
	commitment, err := figure6Commitment(sid, 1, rho, public, schnorrCommitment, decommitment, planHash)
	if err != nil {
		t.Fatal(err)
	}
	mutated := bytes.Clone(decommitment)
	mutated[0] ^= 1
	other, err := figure6Commitment(sid, 1, rho, public, schnorrCommitment, mutated, planHash)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(commitment, other) {
		t.Fatal("Figure 6 commitment ignored decommitment")
	}
}
