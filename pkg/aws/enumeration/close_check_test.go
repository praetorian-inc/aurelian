package enumeration_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNewEnumeratorRequiresClose is a static-analysis test that walks every
// non-test .go file in the repository and verifies: if a function body calls
// the AWS enumeration.NewEnumerator, then that same function must contain a
// defer …Close() call. This prevents new modules from silently dropping the
// skip summary.
//
// This is the compile-time enforcement layer — it fails the test suite if a
// caller of NewEnumerator forgets defer lister.Close().
func TestNewEnumeratorRequiresClose(t *testing.T) {
	repoRoot := findRepoRoot(t)
	fset := token.NewFileSet()
	var violations []string

	err := filepath.Walk(repoRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			base := info.Name()
			if base == "vendor" || base == "testdata" || strings.HasPrefix(base, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		// Only scan non-test Go files.
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		f, parseErr := parser.ParseFile(fset, path, nil, 0)
		if parseErr != nil {
			return nil
		}

		// Only inspect files that import the AWS enumeration package.
		if !importsAWSEnumeration(f) {
			return nil
		}

		ast.Inspect(f, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				return true
			}

			if !bodyCallsNewEnumerator(fn.Body) {
				return true
			}

			if !bodyHasDeferClose(fn.Body) {
				pos := fset.Position(fn.Pos())
				violations = append(violations, pos.String()+": "+fn.Name.Name)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk repo: %v", err)
	}

	for _, v := range violations {
		t.Errorf("NewEnumerator called without defer …Close(): %s", v)
	}
}

// importsAWSEnumeration checks whether the file imports the AWS enumeration
// package (pkg/aws/enumeration), not the GCP or other variants.
func importsAWSEnumeration(f *ast.File) bool {
	for _, imp := range f.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		if strings.HasSuffix(path, "pkg/aws/enumeration") {
			return true
		}
	}
	return false
}

// bodyCallsNewEnumerator reports whether the AST body contains a call to
// a function named NewEnumerator (regardless of package qualifier).
func bodyCallsNewEnumerator(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if nameMatches(call.Fun, "NewEnumerator") {
			found = true
		}
		return !found
	})
	return found
}

// bodyHasDeferClose reports whether the AST body contains a defer statement
// that calls a method named Close.
func bodyHasDeferClose(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		ds, ok := n.(*ast.DeferStmt)
		if !ok {
			return true
		}
		if nameMatches(ds.Call.Fun, "Close") {
			found = true
		}
		return !found
	})
	return found
}

// nameMatches checks whether an expression's rightmost identifier is name.
func nameMatches(expr ast.Expr, name string) bool {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name == name
	case *ast.SelectorExpr:
		return e.Sel.Name == name
	}
	return false
}

// findRepoRoot walks up from the working directory looking for a go.mod file.
func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repo root (no go.mod)")
		}
		dir = parent
	}
}
