package ed25519

import "testing"

func TestFROSTReconstructSecretKeyLimits(t *testing.T) {
	t.Parallel()

	share := frostKeygenInner(t, 1, 1)[1]
	if _, err := ReconstructSecretKey(share); err == nil {
		t.Fatal("production reconstruction accepted a 1-of-1 key share")
	}

	secret, err := ReconstructSecretKeyWithLimits(testLimits(), share)
	if err != nil {
		t.Fatalf("explicit test limits rejected 1-of-1 reconstruction: %v", err)
	}
	defer secret.Destroy()
	publicKey, err := secret.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	metadata := mustKeyShareMetadata(t, share)
	if !publicKey.Equal(metadata.PublicKey) {
		t.Fatal("reconstructed secret does not match the key share public key")
	}
}
