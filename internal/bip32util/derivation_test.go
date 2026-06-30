package bip32util

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/testutil"
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

	ed25519HDVectorParentPubHex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
	ed25519HDVectorChainCodeHex = "2810999a530b5e7f455a3a97c36e0e23b3de096b69343ddfe87730990506b268"
)

type testXPub struct {
	Version           [4]byte
	Depth             uint8
	ParentFingerprint [4]byte
	ChildNumber       uint32
	ChainCode         [ChainCodeSize]byte
	PublicKey         []byte
}

func TestDeriveSecp256k1BIP32Vectors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		parentXPub string
		wantXPub   string
		path       []uint32
	}{
		{name: "TV1: m/0H/1", parentXPub: xpubTV1M0H, wantXPub: xpubTV1M0H1, path: []uint32{1}},
		{name: "TV1: m/0H/1/2H/2", parentXPub: xpubTV1M0H12H, wantXPub: xpubTV1M0H12H2, path: []uint32{2}},
		{name: "TV1: m/0H/1/2H/2/1000000000", parentXPub: xpubTV1M0H12H2, wantXPub: xpubTV1M0H12H21000000000, path: []uint32{1000000000}},
		{name: "TV2: m/0", parentXPub: xpubTV2Master, wantXPub: xpubTV2M0, path: []uint32{0}},
		{name: "TV2: m/0/2147483647H/1", parentXPub: xpubTV2M02147483647H, wantXPub: xpubTV2M02147483647H1, path: []uint32{1}},
		{name: "TV2: m/0/2147483647H/1/2147483646H/2", parentXPub: xpubTV2M02147483647H12147483646H, wantXPub: xpubTV2M02147483647H12147483646H2, path: []uint32{2}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			parent := mustParseTestXPub(t, tc.parentXPub)
			want := mustParseTestXPub(t, tc.wantXPub)

			result, err := DeriveSecp256k1(parent.PublicKey, parent.ChainCode[:], tc.path)
			if err != nil {
				t.Fatalf("DeriveSecp256k1: %v", err)
			}
			assertSecpResultMatchesXPub(t, result, want)
			assertSecpShiftDerivesChild(t, parent.PublicKey, result)
		})
	}
}

func TestDeriveSecp256k1MultiStepConsistency(t *testing.T) {
	t.Parallel()

	root := mustParseTestXPub(t, xpubTV2Master)
	direct, err := DeriveSecp256k1(root.PublicKey, root.ChainCode[:], []uint32{0, 1, 2})
	if err != nil {
		t.Fatal(err)
	}
	step1, err := DeriveSecp256k1(root.PublicKey, root.ChainCode[:], []uint32{0})
	if err != nil {
		t.Fatal(err)
	}
	step2, err := DeriveSecp256k1(step1.ChildPublicKey, step1.ChildChainCode, []uint32{1})
	if err != nil {
		t.Fatal(err)
	}
	chained, err := DeriveSecp256k1(step2.ChildPublicKey, step2.ChildChainCode, []uint32{2})
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(direct.ChildPublicKey, chained.ChildPublicKey) {
		t.Fatal("multi-step vs chained public key mismatch")
	}
	if !bytes.Equal(direct.ChildChainCode, chained.ChildChainCode) {
		t.Fatal("multi-step vs chained chain code mismatch")
	}
	assertSecpShiftDerivesChild(t, root.PublicKey, direct)
}

func TestDeriveSecp256k1RejectsInvalidInputs(t *testing.T) {
	t.Parallel()

	valid := mustParseTestXPub(t, xpubTV2Master)
	tests := []struct {
		name    string
		pub     []byte
		chain   []byte
		path    []uint32
		wantErr error
	}{
		{name: "nil chain code", pub: valid.PublicKey, chain: nil, path: []uint32{0}, wantErr: tss.ErrChainCodeRequired},
		{name: "empty chain code", pub: valid.PublicKey, chain: []byte{}, path: []uint32{0}, wantErr: tss.ErrChainCodeRequired},
		{name: "short chain code", pub: valid.PublicKey, chain: make([]byte, 31), path: []uint32{0}, wantErr: tss.ErrInvalidChainCodeLength},
		{name: "long chain code", pub: valid.PublicKey, chain: make([]byte, 33), path: []uint32{0}, wantErr: tss.ErrInvalidChainCodeLength},
		{name: "path too long", pub: valid.PublicKey, chain: valid.ChainCode[:], path: makeSequentialPath(256), wantErr: tss.ErrDerivationDepthOverflow},
		{name: "hardened index in path", pub: valid.PublicKey, chain: valid.ChainCode[:], path: []uint32{0, tss.HardenedKeyStart}, wantErr: tss.ErrHardenedDerivationUnsupported},
		{name: "hardened first index", pub: valid.PublicKey, chain: valid.ChainCode[:], path: []uint32{tss.HardenedKeyStart + 1}, wantErr: tss.ErrHardenedDerivationUnsupported},
		{name: "invalid public key prefix", pub: invalidPublicKeyPrefix(valid.PublicKey), chain: valid.ChainCode[:], path: []uint32{0}, wantErr: tss.ErrInvalidPublicKey},
		{name: "wrong public key length", pub: make([]byte, 32), chain: valid.ChainCode[:], path: []uint32{0}, wantErr: tss.ErrInvalidPublicKey},
		{name: "all-zero public key", pub: make([]byte, 33), chain: valid.ChainCode[:], path: []uint32{0}, wantErr: tss.ErrInvalidPublicKey},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := DeriveSecp256k1(tc.pub, tc.chain, tc.path)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("expected %v, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestDeriveSecp256k1EmptyPathReturnsParent(t *testing.T) {
	t.Parallel()

	valid := mustParseTestXPub(t, xpubTV2Master)
	for _, path := range []tss.DerivationPath{nil, {}} {
		result, err := DeriveSecp256k1(valid.PublicKey, valid.ChainCode[:], path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(result.ChildPublicKey, valid.PublicKey) {
			t.Fatal("empty path child public key should equal parent")
		}
		if !bytes.Equal(result.ChildChainCode, valid.ChainCode[:]) {
			t.Fatal("empty path child chain code should equal parent")
		}
		if !testutil.IsZeroBytes(result.AdditiveShift) {
			t.Fatal("empty path additive shift should be zero")
		}
	}
}

func TestDeriveSecp256k1MetadataAndSerialization(t *testing.T) {
	t.Parallel()

	parent := mustParseTestXPub(t, xpubTV2Master)
	result, err := DeriveSecp256k1(parent.PublicKey, parent.ChainCode[:], []uint32{0, 1, 2})
	if err != nil {
		t.Fatal(err)
	}
	if result.Depth != 3 {
		t.Fatalf("depth = %d, want 3", result.Depth)
	}
	if result.ChildNumber != 2 {
		t.Fatalf("child number = %d, want 2", result.ChildNumber)
	}
	if len(result.RequestedPath) != 3 || len(result.ResolvedPath) != 3 {
		t.Fatalf("path metadata lengths = requested %d resolved %d, want 3", len(result.RequestedPath), len(result.ResolvedPath))
	}
	parentOfFinal, err := DeriveSecp256k1(parent.PublicKey, parent.ChainCode[:], []uint32{0, 1})
	if err != nil {
		t.Fatal(err)
	}
	wantFP := ComputeFingerprint(parentOfFinal.ChildPublicKey)
	if result.ParentFingerprint != wantFP {
		t.Fatalf("parent fingerprint = %x, want %x", result.ParentFingerprint, wantFP)
	}
}

func TestDeriveEd25519KhovratovichLawVectors(t *testing.T) {
	t.Parallel()

	parentPub := testutil.MustDecodeHex(t, ed25519HDVectorParentPubHex)
	chainCode := testutil.MustDecodeHex(t, ed25519HDVectorChainCodeHex)
	tests := []struct {
		name      string
		index     uint32
		wantChain string
	}{
		{name: "index=0", index: 0, wantChain: "9abd5509ba8a7a2350ce449e081f340f731f948792aa863888db8840b3b29064"},
		{name: "index=1", index: 1, wantChain: "20e93e203c1644a779dcd2ac88f8a8f984369ff886164363c3512e1a9196df15"},
		{name: "index=42", index: 42, wantChain: "328611b9d5d3d5ea3ed8d65a9658fc40a31fdc27f47752d8b6179fb738342317"},
		{name: "index=2147483647", index: 2147483647, wantChain: "2577db087974a0bcc158c2b39e93b57557babb250e9d22f42bce9800a5c91cfa"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			result, err := DeriveEd25519KhovratovichLaw(parentPub, chainCode, []uint32{tc.index})
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(result.ChildChainCode); got != tc.wantChain {
				t.Fatalf("child chain code = %s, want %s", got, tc.wantChain)
			}
			assertEd25519ShiftDerivesChild(t, parentPub, result)
		})
	}
}

func TestDeriveEd25519KhovratovichLawMultiStepConsistency(t *testing.T) {
	t.Parallel()

	parentPub := testutil.MustDecodeHex(t, ed25519HDVectorParentPubHex)
	chainCode := testutil.MustDecodeHex(t, ed25519HDVectorChainCodeHex)
	direct, err := DeriveEd25519KhovratovichLaw(parentPub, chainCode, []uint32{0, 1})
	if err != nil {
		t.Fatal(err)
	}
	step1, err := DeriveEd25519KhovratovichLaw(parentPub, chainCode, []uint32{0})
	if err != nil {
		t.Fatal(err)
	}
	chained, err := DeriveEd25519KhovratovichLaw(step1.ChildPublicKey, step1.ChildChainCode, []uint32{1})
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(direct.ChildPublicKey, chained.ChildPublicKey) {
		t.Fatal("multi-step vs chained public key mismatch")
	}
	if !bytes.Equal(direct.ChildChainCode, chained.ChildChainCode) {
		t.Fatal("multi-step vs chained chain code mismatch")
	}
}

func TestDeriveEd25519KhovratovichLawRejectsInvalidInputs(t *testing.T) {
	t.Parallel()

	pub := testutil.MustDecodeHex(t, ed25519HDVectorParentPubHex)
	chain := testutil.MustDecodeHex(t, ed25519HDVectorChainCodeHex)
	tests := []struct {
		name    string
		pub     []byte
		chain   []byte
		path    []uint32
		wantErr error
	}{
		{name: "depth overflow", pub: pub, chain: chain, path: makePath(256, 0), wantErr: tss.ErrDerivationDepthOverflow},
		{name: "hardened first index", pub: pub, chain: chain, path: []uint32{tss.HardenedKeyStart}, wantErr: tss.ErrHardenedDerivationUnsupported},
		{name: "hardened index later in path", pub: pub, chain: chain, path: []uint32{0, tss.HardenedKeyStart}, wantErr: tss.ErrHardenedDerivationUnsupported},
		{name: "nil chain code", pub: pub, chain: nil, path: []uint32{0}, wantErr: tss.ErrChainCodeRequired},
		{name: "empty chain code", pub: pub, chain: []byte{}, path: []uint32{0}, wantErr: tss.ErrChainCodeRequired},
		{name: "short chain code", pub: pub, chain: make([]byte, 31), path: []uint32{0}, wantErr: tss.ErrInvalidChainCodeLength},
		{name: "invalid public key", pub: make([]byte, 31), chain: chain, path: []uint32{0}, wantErr: tss.ErrInvalidPublicKey},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := DeriveEd25519KhovratovichLaw(tc.pub, tc.chain, tc.path)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("expected %v, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestDeriveEd25519KhovratovichLawEmptyPathReturnsParent(t *testing.T) {
	t.Parallel()

	pub := testutil.MustDecodeHex(t, ed25519HDVectorParentPubHex)
	chain := testutil.MustDecodeHex(t, ed25519HDVectorChainCodeHex)
	for _, path := range []tss.DerivationPath{nil, {}} {
		result, err := DeriveEd25519KhovratovichLaw(pub, chain, path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(result.ChildPublicKey, pub) {
			t.Fatal("empty path child public key should equal parent")
		}
		if !bytes.Equal(result.ChildChainCode, chain) {
			t.Fatal("empty path child chain code should equal parent")
		}
		if !testutil.IsZeroBytes(result.AdditiveShift) {
			t.Fatal("empty path additive shift should be zero")
		}
	}
}

func mustParseTestXPub(t testing.TB, raw string) *testXPub {
	t.Helper()

	payload, err := Base58CheckDecode(raw)
	if err != nil {
		t.Fatalf("parse xpub: %v", err)
	}
	if len(payload) != BIP32ExtendedKeyPayloadLen {
		t.Fatalf("xpub payload length = %d, want %d", len(payload), BIP32ExtendedKeyPayloadLen)
	}
	var x testXPub
	copy(x.Version[:], payload[0:4])
	x.Depth = payload[4]
	copy(x.ParentFingerprint[:], payload[5:9])
	x.ChildNumber = uint32(payload[9])<<24 | uint32(payload[10])<<16 | uint32(payload[11])<<8 | uint32(payload[12])
	copy(x.ChainCode[:], payload[13:45])
	x.PublicKey = bytes.Clone(payload[45:])
	if _, err := secp.PointFromBytes(x.PublicKey); err != nil {
		t.Fatalf("invalid xpub point: %v", err)
	}
	return &x
}

func assertSecpResultMatchesXPub(t testing.TB, got *tss.DerivationResult, want *testXPub) {
	t.Helper()

	if !bytes.Equal(got.ChildPublicKey, want.PublicKey) {
		t.Fatalf("public key mismatch:\n  got: %x\n want: %x", got.ChildPublicKey, want.PublicKey)
	}
	if !bytes.Equal(got.ChildChainCode, want.ChainCode[:]) {
		t.Fatalf("chain code mismatch:\n  got: %x\n want: %x", got.ChildChainCode, want.ChainCode[:])
	}
}

func assertSecpShiftDerivesChild(t testing.TB, parentPub []byte, got *tss.DerivationResult) {
	t.Helper()

	base, err := secp.PointFromBytes(parentPub)
	if err != nil {
		t.Fatal(err)
	}
	shift, err := secp.ScalarFromBytesAllowZero(got.AdditiveShift)
	if err != nil {
		t.Fatal(err)
	}
	child, err := secp.PointBytes(secp.Add(base, secp.ScalarBaseMult(shift)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(child, got.ChildPublicKey) {
		t.Fatal("additive shift does not produce child public key")
	}
}

func assertEd25519ShiftDerivesChild(t testing.TB, parentPub []byte, got *tss.DerivationResult) {
	t.Helper()

	parentPoint, err := edcurve.PointFromBytes(parentPub)
	if err != nil {
		t.Fatal(err)
	}
	shift, err := edcurve.ScalarFromCanonical(got.AdditiveShift)
	if err != nil {
		t.Fatal(err)
	}
	child, err := deriveEd25519PublicKey(parentPoint, shift)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(child, got.ChildPublicKey) {
		t.Fatal("additive shift does not produce child public key")
	}
	if _, err := edcurve.PointFromBytes(got.ChildPublicKey); err != nil {
		t.Fatal(err)
	}
}

func makeSequentialPath(n int) []uint32 {
	path := make([]uint32, n)
	for i := range path {
		path[i] = uint32(i)
	}
	return path
}

func makePath(n int, value uint32) []uint32 {
	path := make([]uint32, n)
	for i := range path {
		path[i] = value
	}
	return path
}

func invalidPublicKeyPrefix(pub []byte) []byte {
	invalid := bytes.Clone(pub)
	invalid[0] = 0x04
	return invalid
}
