package paillier

import (
	"bytes"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSchnorrSourceHasNoBigIntBoundary(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	dir := filepath.Join(root, "internal", "zk", "schnorr")
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range files {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		file := parseGoFile(t, path)
		for _, imp := range file.Imports {
			if imp.Path.Value == `"math/big"` {
				t.Fatalf("%s imports math/big", entry.Name())
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, _ := selector.X.(*ast.Ident)
			if ident != nil && ident.Name == "big" && selector.Sel.Name == "Int" {
				t.Fatalf("%s references big.Int", entry.Name())
			}
			if selector.Sel.Name == "ScalarFromBigInt" {
				t.Fatalf("%s references ScalarFromBigInt", entry.Name())
			}
			return true
		})
	}
}

func TestSecretBearingFieldsUseFixedSecretTypes(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	expectations := []struct {
		path   string
		typeID string
		fields map[string]string
	}{
		{
			path:   "internal/paillier/paillier.go",
			typeID: "PrivateKey",
			fields: map[string]string{"P": "*secret.Scalar", "Q": "*secret.Scalar"},
		},
		{
			path:   "internal/mta/start.go",
			typeID: "StartOpening",
			fields: map[string]string{"k": "*secret.Scalar", "rho": "*secret.Scalar"},
		},
		{
			path:   "internal/zk/paillier/enc.go",
			typeID: "EncWitness",
			fields: map[string]string{"K": "*secret.Scalar", "Rho": "*secret.Scalar"},
		},
		{
			path:   "internal/zk/paillier/affg.go",
			typeID: "AffGWitness",
			fields: map[string]string{
				"X": "*secret.Scalar", "Y": "*secret.Scalar",
				"Rho": "*secret.Scalar", "RhoY": "*secret.Scalar",
			},
		},
		{
			path:   "internal/zk/paillier/logstar.go",
			typeID: "LogStarWitness",
			fields: map[string]string{"X": "*secret.Scalar", "Rho": "*secret.Scalar"},
		},
	}
	for _, expectation := range expectations {
		t.Run(expectation.typeID, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(root, expectation.path)
			file := parseGoFile(t, path)
			actual := structFieldTypes(t, file, expectation.typeID)
			for name, want := range expectation.fields {
				if got := actual[name]; got != want {
					t.Fatalf("%s.%s type = %q, want %q", expectation.typeID, name, got, want)
				}
			}
		})
	}
}

func TestBigIntExpCallSitesRemainPublicExponentOnly(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	allowed := map[string]map[string]bool{
		"internal/paillier/crypto.go": {
			"EncryptWithRandomness": true,
		},
		"internal/zk/paillier/group.go": {
			"OMulPublic": true,
		},
		"internal/zk/paillier/ring_pedersen.go": {
			"ExpSignedMod":       true,
			"VerifyRingPedersen": true,
		},
		"internal/zk/paillier/modulus.go": {
			"VerifyModulus":             true,
			"fourthRootForModulusProof": true,
		},
		"internal/zk/paillier/enc.go": {
			"proveEncOnce": true,
		},
		"internal/zk/paillier/affg.go": {
			"proveAffGOnce": true,
		},
		"internal/zk/paillier/logstar.go": {
			"proveLogStarOnce": true,
		},
	}
	directories := []string{
		filepath.Join(root, "internal", "paillier"),
		filepath.Join(root, "internal", "mta"),
		filepath.Join(root, "internal", "zk", "paillier"),
	}
	for _, directory := range directories {
		err := filepath.WalkDir(directory, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				if entry.Name() == "paillierct" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				return nil
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			file := parseGoFile(t, path)
			for _, declaration := range file.Decls {
				function, ok := declaration.(*ast.FuncDecl)
				if !ok || function.Body == nil {
					continue
				}
				ast.Inspect(function.Body, func(node ast.Node) bool {
					call, ok := node.(*ast.CallExpr)
					if !ok {
						return true
					}
					selector, ok := call.Fun.(*ast.SelectorExpr)
					if !ok || selector.Sel.Name != "Exp" {
						return true
					}
					if !allowed[relative][function.Name.Name] {
						t.Fatalf("%s adds an unaudited Exp call in %s", relative, function.Name.Name)
					}
					return true
				})
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate repository root")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(current), "..", "..", ".."))
}

func parseGoFile(t *testing.T, path string) *ast.File {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	return file
}

func structFieldTypes(t *testing.T, file *ast.File, typeID string) map[string]string {
	t.Helper()
	out := make(map[string]string)
	for _, declaration := range file.Decls {
		gen, ok := declaration.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gen.Specs {
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok || typeSpec.Name.Name != typeID {
				continue
			}
			structType, ok := typeSpec.Type.(*ast.StructType)
			if !ok {
				t.Fatalf("%s is not a struct", typeID)
			}
			for _, field := range structType.Fields.List {
				var rendered bytes.Buffer
				if err := format.Node(&rendered, token.NewFileSet(), field.Type); err != nil {
					t.Fatal(err)
				}
				for _, name := range field.Names {
					out[name.Name] = rendered.String()
				}
			}
			return out
		}
	}
	t.Fatalf("type %s not found", typeID)
	return nil
}
