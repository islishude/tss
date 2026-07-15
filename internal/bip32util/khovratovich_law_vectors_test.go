package bip32util

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"slices"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testvectors"
)

const khovratovichLawVectorPath = "protocol/ed25519-bip32/khovratovich_law_vectors.json"

type khovratovichLawVectorFile struct {
	Format     string                          `json:"format"`
	Algorithm  string                          `json:"algorithm"`
	Provenance khovratovichLawVectorProvenance `json:"provenance"`
	Vectors    []khovratovichLawPublicVector   `json:"vectors"`
}

type khovratovichLawVectorProvenance struct {
	PaperURL             string   `json:"paper_url"`
	OracleName           string   `json:"oracle_name"`
	OracleVersion        string   `json:"oracle_version"`
	ReleaseURL           string   `json:"release_url"`
	TagCommit            string   `json:"tag_commit"`
	ReleaseAsset         string   `json:"release_asset"`
	ReleaseAssetURL      string   `json:"release_asset_url"`
	ReleaseAssetSHA256   string   `json:"release_asset_sha256"`
	ReleaseAssetPlatform string   `json:"release_asset_platform"`
	VersionOutput        string   `json:"version_output"`
	Commands             []string `json:"commands"`
	CLIPathConstraint    string   `json:"cli_path_constraint"`
	PublicVectorMethod   string   `json:"public_vector_method"`
	Notes                string   `json:"notes"`
}

type khovratovichLawPublicVector struct {
	Name             string   `json:"name"`
	Path             []uint32 `json:"path"`
	OracleParentPath []uint32 `json:"oracle_parent_path"`
	OracleChildPath  []uint32 `json:"oracle_child_path"`
	ParentPublicKey  string   `json:"parent_public_key"`
	ParentChainCode  string   `json:"parent_chain_code"`
	ChildPublicKey   string   `json:"child_public_key"`
	ChildChainCode   string   `json:"child_chain_code"`
}

func TestDeriveEd25519KhovratovichLawIndependentPublicVectors(t *testing.T) {
	t.Parallel()

	vectors := readKhovratovichLawVectors(t)
	assertKhovratovichLawProvenance(t, vectors)

	wantPaths := map[string][]uint32{
		"path_0":          {0},
		"path_0_1":        {0, 1},
		"path_2147483647": {tss.HardenedKeyStart - 1},
	}
	if len(vectors.Vectors) != len(wantPaths) {
		t.Fatalf("vector count = %d, want %d", len(vectors.Vectors), len(wantPaths))
	}

	seen := make(map[string]struct{}, len(vectors.Vectors))
	for _, vector := range vectors.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			wantPath, ok := wantPaths[vector.Name]
			if !ok {
				t.Fatalf("unexpected vector name %q", vector.Name)
			}
			if !slices.Equal(vector.Path, wantPath) {
				t.Fatalf("path = %v, want %v", vector.Path, wantPath)
			}
			if _, duplicate := seen[vector.Name]; duplicate {
				t.Fatalf("duplicate vector name %q", vector.Name)
			}
			seen[vector.Name] = struct{}{}

			wantOracleChildPath := slices.Concat(vector.OracleParentPath, vector.Path)
			if !slices.Equal(vector.OracleChildPath, wantOracleChildPath) {
				t.Fatalf("oracle child path = %v, want parent path plus vector path %v", vector.OracleChildPath, wantOracleChildPath)
			}
			for _, index := range vector.OracleChildPath {
				if index >= tss.HardenedKeyStart {
					t.Fatalf("oracle path contains hardened index %d", index)
				}
			}

			parentPublicKey := decodeKhovratovichLawHex(t, "parent public key", vector.ParentPublicKey)
			parentChainCode := decodeKhovratovichLawHex(t, "parent chain code", vector.ParentChainCode)
			wantChildPublicKey := decodeKhovratovichLawHex(t, "child public key", vector.ChildPublicKey)
			wantChildChainCode := decodeKhovratovichLawHex(t, "child chain code", vector.ChildChainCode)

			result, err := DeriveEd25519KhovratovichLaw(parentPublicKey, parentChainCode, tss.DerivationPath(vector.Path))
			if err != nil {
				t.Fatalf("derive oracle path: %v", err)
			}
			if !bytes.Equal(result.ChildPublicKey, wantChildPublicKey) {
				t.Fatalf("child public key mismatch: got %x, want %x", result.ChildPublicKey, wantChildPublicKey)
			}
			if !bytes.Equal(result.ChildChainCode, wantChildChainCode) {
				t.Fatalf("child chain code mismatch: got %x, want %x", result.ChildChainCode, wantChildChainCode)
			}
			if !slices.Equal(result.RequestedPath, tss.DerivationPath(vector.Path)) || !slices.Equal(result.ResolvedPath, tss.DerivationPath(vector.Path)) {
				t.Fatalf("resolved path metadata = requested %v resolved %v, want %v", result.RequestedPath, result.ResolvedPath, vector.Path)
			}

			stepPublicKey := parentPublicKey
			stepChainCode := parentChainCode
			for _, index := range vector.Path {
				step, err := DeriveEd25519KhovratovichLaw(stepPublicKey, stepChainCode, tss.DerivationPath{index})
				if err != nil {
					t.Fatalf("derive chained index %d: %v", index, err)
				}
				stepPublicKey = step.ChildPublicKey
				stepChainCode = step.ChildChainCode
			}
			if !bytes.Equal(stepPublicKey, wantChildPublicKey) || !bytes.Equal(stepChainCode, wantChildChainCode) {
				t.Fatal("multi-step derivation differs from repeated parent-to-child derivation")
			}
		})
	}
}

func readKhovratovichLawVectors(t *testing.T) khovratovichLawVectorFile {
	t.Helper()

	decoder := json.NewDecoder(bytes.NewReader(testvectors.Read(t, khovratovichLawVectorPath)))
	decoder.DisallowUnknownFields()
	var vectors khovratovichLawVectorFile
	if err := decoder.Decode(&vectors); err != nil {
		t.Fatalf("decode vector file: %v", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		t.Fatalf("vector file has trailing JSON: %v", err)
	}
	return vectors
}

func assertKhovratovichLawProvenance(t *testing.T, vectors khovratovichLawVectorFile) {
	t.Helper()

	if vectors.Format != "tss-ed25519-bip32-khovratovich-law-public-v1" {
		t.Fatalf("format = %q", vectors.Format)
	}
	if vectors.Algorithm != "Khovratovich-Law Ed25519-BIP32 non-hardened public derivation" {
		t.Fatalf("algorithm = %q", vectors.Algorithm)
	}
	provenance := vectors.Provenance
	checks := []struct {
		name string
		got  string
		want string
	}{
		{
			name: "paper URL",
			got:  provenance.PaperURL,
			want: "https://input-output-hk.github.io/adrestia/static/Ed25519_BIP.pdf",
		},
		{name: "oracle name", got: provenance.OracleName, want: "cardano-address"},
		{
			name: "oracle version",
			got:  provenance.OracleVersion,
			want: "4.0.7",
		},
		{
			name: "release URL",
			got:  provenance.ReleaseURL,
			want: "https://github.com/IntersectMBO/cardano-addresses/releases/tag/4.0.7",
		},
		{
			name: "tag commit",
			got:  provenance.TagCommit,
			want: "a6b7c3d87ea306c3b21bb096bf8cf23fbf7c93c7",
		},
		{
			name: "release asset",
			got:  provenance.ReleaseAsset,
			want: "cardano-address-4.0.7-macos.tar.gz",
		},
		{
			name: "release asset URL",
			got:  provenance.ReleaseAssetURL,
			want: "https://github.com/IntersectMBO/cardano-addresses/releases/download/4.0.7/cardano-address-4.0.7-macos.tar.gz",
		},
		{
			name: "release asset SHA-256",
			got:  provenance.ReleaseAssetSHA256,
			want: "f7ea1c2ab700120a11d5246a35844d967a486b2de0086a8cef264acced73e05a",
		},
		{name: "release asset platform", got: provenance.ReleaseAssetPlatform, want: "macOS arm64"},
		{name: "version output", got: provenance.VersionOutput, want: "4.0.7 @ unknown"},
	}
	for _, check := range checks {
		if check.got != check.want {
			t.Fatalf("%s = %q, want %q", check.name, check.got, check.want)
		}
	}
	wantCommands := []string{
		"printf '%s\\n' 'acct_xvk1z0v5g7g3pfz7vd2079cptgvkxlzvuwy2z40n6anqm99yhsseaveacz7gvcdfvn86v6yxr2pv2shs3dh9frmq4zh6g8yqjmkg95zx2ds9dyp0h' | cardano-address key inspect",
		"printf '%s\\n' 'acct_xvk1z0v5g7g3pfz7vd2079cptgvkxlzvuwy2z40n6anqm99yhsseaveacz7gvcdfvn86v6yxr2pv2shs3dh9frmq4zh6g8yqjmkg95zx2ds9dyp0h' | cardano-address key child 0/0 | cardano-address key inspect",
		"printf '%s\\n' 'acct_xvk1z0v5g7g3pfz7vd2079cptgvkxlzvuwy2z40n6anqm99yhsseaveacz7gvcdfvn86v6yxr2pv2shs3dh9frmq4zh6g8yqjmkg95zx2ds9dyp0h' | cardano-address key child 0/1 | cardano-address key inspect",
		"printf '%s\\n' 'acct_xvk1z0v5g7g3pfz7vd2079cptgvkxlzvuwy2z40n6anqm99yhsseaveacz7gvcdfvn86v6yxr2pv2shs3dh9frmq4zh6g8yqjmkg95zx2ds9dyp0h' | cardano-address key child 0/2147483647 | cardano-address key inspect",
	}
	if !slices.Equal(provenance.Commands, wantCommands) {
		t.Fatal("oracle commands do not match the recorded one-time invocation")
	}
	if provenance.CLIPathConstraint == "" || provenance.PublicVectorMethod == "" || provenance.Notes == "" {
		t.Fatal("oracle provenance explanation is incomplete")
	}
	decodeKhovratovichLawHex(t, "release asset SHA-256", provenance.ReleaseAssetSHA256)
}

func decodeKhovratovichLawHex(t *testing.T, name, value string) []byte {
	t.Helper()

	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("%s is not hexadecimal: %v", name, err)
	}
	if len(decoded) != 32 {
		t.Fatalf("%s length = %d bytes, want 32", name, len(decoded))
	}
	if hex.EncodeToString(decoded) != value {
		t.Fatalf("%s is not canonical lowercase hexadecimal", name)
	}
	return decoded
}
