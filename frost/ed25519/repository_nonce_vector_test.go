package ed25519

import (
	"bytes"
	"slices"
	"testing"

	"github.com/islishude/tss/internal/testutil"
)

// TestRepositoryBoundStartSignNonceVector fixes the production StartSign
// derivation separately from the exact RFC Appendix E.1 nonce primitive. It
// reuses E.1's public key material and randomness but includes the repository's
// session, message, context, plan, and nonce-role binding.
func TestRepositoryBoundStartSignNonceVector(t *testing.T) {
	t.Parallel()
	v := rfc9591Ed25519Vector(t)
	key1 := rfc9591KeyShare(t, 1, v.p1Share, v)
	key3 := rfc9591KeyShare(t, 3, v.p3Share, v)
	sessionID := testutil.MustSessionID(9591)

	s1, out1, err := startFROSTSignWithOptions(key1, sessionID, v.signers, v.message, testSignOptions{
		NonceReader: bytes.NewReader(slices.Concat(v.p1HidingRandomness, v.p1BindingRandomness)),
	})
	if err != nil {
		t.Fatal(err)
	}
	s3, out3, err := startFROSTSignWithOptions(key3, sessionID, v.signers, v.message, testSignOptions{
		NonceReader: bytes.NewReader(slices.Concat(v.p3HidingRandomness, v.p3BindingRandomness)),
	})
	if err != nil {
		t.Fatal(err)
	}

	assertCommitmentEnvelope(
		t,
		out1[0],
		hexMust(t, "be951d308fa82961b7061b5bb54b68452712035d1358e00a59dd3a86c51fa352"),
		hexMust(t, "5f08247413ff39ecfc0297a7625b3d95ad9a0833ede310b78074272fbbab52eb"),
	)
	assertCommitmentEnvelope(
		t,
		out3[0],
		hexMust(t, "e7c556f3e2d846ff5b521cec1b86877389e2982736c793ee3dda6ea6f7cc5e96"),
		hexMust(t, "7d144c5dbc3954ebec05ae2ec9115d200bf23cb852e16922f136fef1495126e7"),
	)

	p1Partial, err := s1.Handle(testutil.DeliverEnvelope(out3[0]))
	if err != nil {
		t.Fatal(err)
	}
	p3Partial, err := s3.Handle(testutil.DeliverEnvelope(out1[0]))
	if err != nil {
		t.Fatal(err)
	}
	assertPartialEnvelope(t, p1Partial[0], hexMust(t, "363960e1e378619df72f823c2826b31e7d710a5dd63f9e3ab5e2b8685324e70d"))
	assertPartialEnvelope(t, p3Partial[0], hexMust(t, "2604097b43163ba87fafb15f34907070d199335a24a349d599ff101fafed420c"))

	if _, err := s1.Handle(testutil.DeliverEnvelope(p3Partial[0])); err != nil {
		t.Fatal(err)
	}
	sig, ok := s1.Signature()
	if !ok {
		t.Fatal("repository-bound vector did not complete")
	}
	wantSignature := hexMust(t, "8da2b632d7898c84e4feae419e7ddb23211e9d55eacb1570b88b2f742e7e9f7f6f6973ff0c2c8aeda0423cf97dbc447a4e0b3eb7fae2e70f4fe2c98702122a0a")
	if !bytes.Equal(sig, wantSignature) {
		t.Fatal("repository-bound signature vector mismatch")
	}
}
