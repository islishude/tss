package tss

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

func TestExportedIdentifiersHaveDocComments(t *testing.T) {
	root := "."
	fset := token.NewFileSet()
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			name := entry.Name()
			if name == ".git" || name == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if ast.IsExported(d.Name.Name) {
					checkDocStartsWith(t, fset, path, d.Doc, d.Name.Name)
				}
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch s := spec.(type) {
					case *ast.TypeSpec:
						if ast.IsExported(s.Name.Name) {
							checkDocStartsWith(t, fset, path, docGroup(s.Doc, d.Doc), s.Name.Name)
						}
					case *ast.ValueSpec:
						for _, name := range s.Names {
							if ast.IsExported(name.Name) {
								checkDocStartsWith(t, fset, path, docGroup(s.Doc, d.Doc), name.Name)
							}
						}
					}
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func docGroup(preferred, fallback *ast.CommentGroup) *ast.CommentGroup {
	if preferred != nil {
		return preferred
	}
	return fallback
}

func checkDocStartsWith(t *testing.T, fset *token.FileSet, path string, doc *ast.CommentGroup, name string) {
	t.Helper()
	if doc == nil {
		t.Errorf("%s: exported %s missing doc comment", path, name)
		return
	}
	text := strings.TrimSpace(doc.Text())
	if !strings.HasPrefix(text, name+" ") && !strings.HasPrefix(text, name+".") {
		pos := fset.Position(doc.Pos())
		t.Errorf("%s:%d: doc for exported %s must start with identifier; got %q", path, pos.Line, name, firstDocLine(text))
	}
}

func firstDocLine(text string) string {
	if i := strings.IndexByte(text, '\n'); i >= 0 {
		return text[:i]
	}
	return text
}
