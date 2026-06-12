package secp256k1

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"testing"

	"github.com/islishude/tss/internal/bip32util"
)

const (
	xpubTV2Master = "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"

	xpubTV1M0H                        = "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
	xpubTV1M0H1                       = "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"
	xpubTV1M0H12H                     = "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5"
	xpubTV1M0H12H2                    = "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV"
	xpubTV1M0H12H21000000000          = "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"
	xpubTV2M0                         = "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"
	xpubTV2M02147483647H              = "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a"
	xpubTV2M02147483647H1             = "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon"
	xpubTV2M02147483647H12147483646H  = "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"
	xpubTV2M02147483647H12147483646H2 = "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt"
)

func mustParseXPub(t testing.TB, raw string) *ExtendedPublicKey {
	t.Helper()

	xpub, err := ParseExtendedPublicKey(raw)
	if err != nil {
		t.Fatalf("parse xpub: %v", err)
	}
	return xpub
}

func assertDerivationMatchesXPub(t testing.TB, got *bip32util.DerivationResult, want *ExtendedPublicKey) {
	t.Helper()

	if !bytes.Equal(got.ChildPublicKey, want.PublicKey) {
		t.Errorf("public key mismatch:\n  got: %x\n want: %x", got.ChildPublicKey, want.PublicKey)
	}
	if !bytes.Equal(got.ChildChainCode, want.ChainCode[:]) {
		t.Errorf("chain code mismatch:\n  got: %x\n want: %x", got.ChildChainCode, want.ChainCode[:])
	}
}

func assertAdditiveShiftDerivesChild(t testing.TB, parent *ExtendedPublicKey, got *bip32util.DerivationResult) {
	t.Helper()

	derivedPub, err := DerivePublicKey(parent.PublicKey, got.AdditiveShift)
	if err != nil {
		t.Fatalf("DerivePublicKey with additive shift: %v", err)
	}
	if !bytes.Equal(derivedPub, got.ChildPublicKey) {
		t.Error("additive shift does not produce child public key")
	}
}

// fakeHMACForInvalidChild forces IL to be a specific value to trigger
// invalid-child conditions for testing.
func fakeHMACForInvalidChild(ilValue []byte) func(key, data []byte) ([]byte, []byte) {
	return func(key, data []byte) ([]byte, []byte) {
		il := make([]byte, 32)
		copy(il, ilValue)
		ir := make([]byte, 32)

		// Use a deterministic IR from the real HMAC for chain-code continuity.
		mac := hmac.New(sha512.New, key)
		mac.Write(data)
		I := mac.Sum(nil)
		copy(ir, I[32:])
		return il, ir
	}
}
