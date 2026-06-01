package enumeration_test

import (
	"fmt"
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
			return fmt.Errorf("parse %s: %w", path, parseErr)
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
		t.Errorf(`%s: NewEnumerator() called without defer Close().

    Add "defer lister.Close()" immediately after the NewEnumerator call:

        lister := cclist.NewEnumerator(opts)
        defer lister.Close()

    Close() logs the skip summary so operators see which (region, service)
    pairs were skipped due to AccessDenied / SCP / opt-in errors.
    Without it, skipped resources are silently lost from the summary.`, v)
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

// TestSkipReportFieldRequiresUsage is a static-analysis test that scans every
// non-test .go file in pkg/aws/enumeration/ and verifies: if a file defines a
// struct with a `skipReport *SkipReport` field, then the same file must also
// contain a call to ClassifySkippable or skipReport.RecordBatch (i.e. the field
// must actually be used, not just stored). This prevents the IAM-style bug where
// a constructor wires the report but the enumerator never records skips.
func TestSkipReportFieldRequiresUsage(t *testing.T) {
	enumDir := filepath.Join(findRepoRoot(t), "pkg", "aws", "enumeration")
	fset := token.NewFileSet()
	var violations []string

	entries, err := os.ReadDir(enumDir)
	if err != nil {
		t.Fatalf("read enumeration dir: %v", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(enumDir, entry.Name())
		f, parseErr := parser.ParseFile(fset, path, nil, 0)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", path, parseErr)
		}

		if !fileHasSkipReportField(f) {
			continue
		}
		if !fileUsesSkipReport(f) {
			violations = append(violations, entry.Name())
		}
	}

	for _, v := range violations {
		t.Errorf(`%s: struct has skipReport *SkipReport field but never uses it.

    Any enumerator that accepts *SkipReport must call ClassifySkippable
    or skipReport.RecordBatch in its enumeration methods. Without this,
    errors are silently lost from the SkipReport summary.

    Example — add to your list/enumerate function:
        if op := ClassifySkippable(err, "myservice", "ListThings", region); op != nil {
            e.skipReport.RecordBatch([]SkippedOp{*op})
            return nil
        }`, v)
	}
}

// fileHasSkipReportField checks if any struct in the file has a field
// named "skipReport" with type "*SkipReport".
func fileHasSkipReportField(f *ast.File) bool {
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		if found {
			return false
		}
		ts, ok := n.(*ast.TypeSpec)
		if !ok {
			return true
		}
		st, ok := ts.Type.(*ast.StructType)
		if !ok {
			return true
		}
		for _, field := range st.Fields.List {
			for _, name := range field.Names {
				if name.Name == "skipReport" {
					found = true
					return false
				}
			}
		}
		return true
	})
	return found
}

// fileUsesSkipReport checks if the file contains a call to ClassifySkippable
// or a selector expression accessing skipReport (e.g. e.skipReport.RecordBatch).
func fileUsesSkipReport(f *ast.File) bool {
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		if found {
			return false
		}
		switch e := n.(type) {
		case *ast.CallExpr:
			if nameMatches(e.Fun, "ClassifySkippable") {
				found = true
			}
		case *ast.SelectorExpr:
			// Match e.skipReport.RecordBatch, e.skipReport.Record, etc.
			if inner, ok := e.X.(*ast.SelectorExpr); ok {
				if inner.Sel.Name == "skipReport" {
					found = true
				}
			}
		}
		return !found
	})
	return found
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
