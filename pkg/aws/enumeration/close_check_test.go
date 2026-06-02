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
// This is the test-time enforcement layer — it fails the test suite if a
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

			varName := newEnumeratorVarName(fn.Body)
			if varName == "" {
				return true // no NewEnumerator call in this function
			}

			if !bodyHasDeferCloseOnVar(fn.Body, varName) {
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

// newEnumeratorVarName finds the variable name assigned from a NewEnumerator
// call (e.g. "lister" from `lister := cclist.NewEnumerator(...)`). Returns ""
// if no NewEnumerator call is found.
func newEnumeratorVarName(body *ast.BlockStmt) string {
	var varName string
	ast.Inspect(body, func(n ast.Node) bool {
		if varName != "" {
			return false
		}
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 || len(assign.Lhs) != 1 {
			return true
		}
		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if !ok || !nameMatches(call.Fun, "NewEnumerator") {
			return true
		}
		if ident, ok := assign.Lhs[0].(*ast.Ident); ok {
			varName = ident.Name
		}
		return varName == ""
	})
	return varName
}

// bodyHasDeferCloseOnVar checks that the function body contains a defer
// statement that calls Close() on the specific variable. Handles both:
//   - defer lister.Close()
//   - defer func() { _ = lister.Close() }()   (linter errcheck pattern)
//
// This prevents false positives from unrelated defer x.Close() calls
// (e.g. os.File, http.Response.Body) that have nothing to do with the
// enumerator.
func bodyHasDeferCloseOnVar(body *ast.BlockStmt, varName string) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		ds, ok := n.(*ast.DeferStmt)
		if !ok {
			return true
		}
		// Direct: defer lister.Close()
		if sel, ok := ds.Call.Fun.(*ast.SelectorExpr); ok {
			if sel.Sel.Name == "Close" {
				if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == varName {
					found = true
					return false
				}
			}
		}
		// Wrapped: defer func() { _ = lister.Close() }()
		if funcLit, ok := ds.Call.Fun.(*ast.FuncLit); ok {
			ast.Inspect(funcLit.Body, func(inner ast.Node) bool {
				if found {
					return false
				}
				call, ok := inner.(*ast.CallExpr)
				if !ok {
					return true
				}
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
					if sel.Sel.Name == "Close" {
						if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == varName {
							found = true
						}
					}
				}
				return !found
			})
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

// fileUsesSkipReport checks that the file contains the correct wiring
// pattern. It verifies THREE things all present in the same file:
//
//  1. An if-statement with ClassifySkippable in the Init:
//     if op := ClassifySkippable(err, ...); op != nil { ... }
//
//  2. A dereference of the result variable (*op) inside the if-body
//     (proves the classified op is captured, not discarded)
//
//  3. A call to skipReport.RecordBatch or skipReport.Record anywhere
//     in the file (proves the captured ops are flushed to the report)
//
// All three are required. This catches:
//   - ClassifySkippable never called → #1 fails
//   - Called but result discarded (no *op) → #2 fails
//   - Result captured but never flushed to report → #3 fails
func fileUsesSkipReport(f *ast.File) bool {
	hasClassifyWithDeref := false
	hasSkipReportCall := false

	ast.Inspect(f, func(n ast.Node) bool {
		// Check #1 + #2: if op := ClassifySkippable(...); op != nil { ...*op... }
		if ifStmt, ok := n.(*ast.IfStmt); ok && ifStmt.Init != nil {
			if assign, ok := ifStmt.Init.(*ast.AssignStmt); ok && len(assign.Rhs) == 1 && len(assign.Lhs) == 1 {
				if call, ok := assign.Rhs[0].(*ast.CallExpr); ok && nameMatches(call.Fun, "ClassifySkippable") {
					if opIdent, ok := assign.Lhs[0].(*ast.Ident); ok {
						if blockHasStarIdent(ifStmt.Body, opIdent.Name) {
							hasClassifyWithDeref = true
						}
					}
				}
			}
		}

		// Check #3: any selector chain ending in skipReport.RecordBatch or skipReport.Record
		if sel, ok := n.(*ast.SelectorExpr); ok {
			if sel.Sel.Name == "RecordBatch" || sel.Sel.Name == "Record" {
				if inner, ok := sel.X.(*ast.SelectorExpr); ok {
					if inner.Sel.Name == "skipReport" {
						hasSkipReportCall = true
					}
				}
			}
		}

		return true
	})

	return hasClassifyWithDeref && hasSkipReportCall
}

// blockHasStarIdent checks if the block contains *name (a star/deref of name).
func blockHasStarIdent(body *ast.BlockStmt, name string) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		star, ok := n.(*ast.StarExpr)
		if !ok {
			return true
		}
		if ident, ok := star.X.(*ast.Ident); ok && ident.Name == name {
			found = true
		}
		return !found
	})
	return found
}

// TestClassifySkippableServiceNames scans every non-test .go file in
// pkg/aws/enumeration/ and verifies that all ClassifySkippable calls pass
// a short lowercase service name (e.g. "amplify", "s3", "iam"), NOT a
// CloudControl type string (e.g. "AWS::Amplify::App"). If someone adds a
// new enumerator and passes the CC type string, this test fails — catching
// the exact bug where inner-loop metadata is wrong and the SkipReport
// would show degraded entries.
func TestClassifySkippableServiceNames(t *testing.T) {
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

		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if !nameMatches(call.Fun, "ClassifySkippable") {
				return true
			}
			// ClassifySkippable(err, service, operation, region)
			// service is the second argument (index 1).
			if len(call.Args) < 2 {
				return true
			}
			lit, ok := call.Args[1].(*ast.BasicLit)
			if !ok {
				// Not a string literal — could be a variable (e.g. in
				// enumerator.go dispatcher). Skip.
				return true
			}
			svc := strings.Trim(lit.Value, `"`)
			if strings.HasPrefix(svc, "AWS::") {
				pos := fset.Position(call.Pos())
				violations = append(violations, fmt.Sprintf(
					"%s: ClassifySkippable uses CloudControl type %q as service name — use the short lowercase name instead (e.g. %q)",
					pos, svc, strings.ToLower(strings.Split(svc, "::")[1])))
			}
			return true
		})
	}

	for _, v := range violations {
		t.Error(v)
	}
}

// TestNewEnumeratorSharesSkipReport verifies two things inside NewEnumerator:
//
//  1. NewSkipReport() is called exactly once (the shared instance).
//  2. Every function call that has an argument named "skipReport" passes the
//     identifier `skipReport` — not a NewSkipReport() call, a helper function,
//     or any other expression. This ensures all enumerators share the same
//     report instance.
func TestNewEnumeratorSharesSkipReport(t *testing.T) {
	enumDir := filepath.Join(findRepoRoot(t), "pkg", "aws", "enumeration")
	fset := token.NewFileSet()
	path := filepath.Join(enumDir, "enumerator.go")
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse enumerator.go: %v", err)
	}

	var violations []string

	ast.Inspect(f, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "NewEnumerator" || fn.Body == nil {
			return true
		}

		// Check 1: exactly one NewSkipReport() call.
		newSkipReportCount := 0
		ast.Inspect(fn.Body, func(inner ast.Node) bool {
			call, ok := inner.(*ast.CallExpr)
			if !ok {
				return true
			}
			if nameMatches(call.Fun, "NewSkipReport") {
				newSkipReportCount++
			}
			return true
		})
		if newSkipReportCount != 1 {
			violations = append(violations, fmt.Sprintf(
				"NewEnumerator has %d NewSkipReport() calls, expected exactly 1", newSkipReportCount))
		}

		// Check 2: every call whose last argument position could be a
		// *SkipReport must pass the identifier `skipReport`, not any
		// other expression.
		ast.Inspect(fn.Body, func(inner ast.Node) bool {
			call, ok := inner.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			// Check every argument — if it's the identifier "skipReport", good.
			// If it's a different expression but resolves to SkipReport, bad.
			// We can't do type resolution in AST, so we use a heuristic:
			// any call to a function named New*Enumerator* or
			// New*CloudControl* must have its last arg be `skipReport`.
			fnName := ""
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				fnName = sel.Sel.Name
			} else if ident, ok := call.Fun.(*ast.Ident); ok {
				fnName = ident.Name
			}
			if !strings.HasPrefix(fnName, "New") {
				return true
			}
			// Check last argument — the *SkipReport is conventionally last.
			lastArg := call.Args[len(call.Args)-1]
			ident, isIdent := lastArg.(*ast.Ident)
			if isIdent && ident.Name == "skipReport" {
				return true // correct — passes the shared variable
			}
			// The last arg is not the `skipReport` identifier.
			// Check if the function is one that accepts *SkipReport.
			// Heuristic: constructor names containing "Enumerator" or
			// "CloudControl" that we know take *SkipReport.
			if strings.Contains(fnName, "Enumerator") || strings.Contains(fnName, "CloudControl") {
				pos := fset.Position(call.Pos())
				argStr := "non-identifier"
				if isIdent {
					argStr = ident.Name
				}
				violations = append(violations, fmt.Sprintf(
					"%s: %s() last arg is %q, expected `skipReport`. "+
						"All enumerators must share the same SkipReport instance.",
					pos, fnName, argStr))
			}
			return true
		})

		return false
	})

	for _, v := range violations {
		t.Error(v)
	}
}

// TestClassifySkippableAlwaysInIfInit verifies that every ClassifySkippable
// call in non-test enumerator files is in an if-statement's Init position:
//
//	if op := ClassifySkippable(...); op != nil { ... }
//
// A bare call like `op := ClassifySkippable(...)` without a nil check would
// panic on `*op` when the error is not skippable. This prevents that class
// of nil-deref bug.
func TestClassifySkippableAlwaysInIfInit(t *testing.T) {
	enumDir := filepath.Join(findRepoRoot(t), "pkg", "aws", "enumeration")
	fset := token.NewFileSet()
	var violations []string

	entries, err := os.ReadDir(enumDir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		// Skip skip_report.go — it defines ClassifySkippable, doesn't call it.
		if entry.Name() == "skip_report.go" {
			continue
		}
		path := filepath.Join(enumDir, entry.Name())
		f, parseErr := parser.ParseFile(fset, path, nil, 0)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", path, parseErr)
		}

		// Collect all ClassifySkippable call positions that ARE in if-inits.
		ifInitPositions := make(map[token.Pos]bool)
		ast.Inspect(f, func(n ast.Node) bool {
			ifStmt, ok := n.(*ast.IfStmt)
			if !ok || ifStmt.Init == nil {
				return true
			}
			if assign, ok := ifStmt.Init.(*ast.AssignStmt); ok {
				for _, rhs := range assign.Rhs {
					if call, ok := rhs.(*ast.CallExpr); ok && nameMatches(call.Fun, "ClassifySkippable") {
						ifInitPositions[call.Pos()] = true
					}
				}
			}
			return true
		})

		// Find ALL ClassifySkippable calls and check they're in the if-init set.
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !nameMatches(call.Fun, "ClassifySkippable") {
				return true
			}
			if !ifInitPositions[call.Pos()] {
				pos := fset.Position(call.Pos())
				violations = append(violations, fmt.Sprintf(
					"%s: ClassifySkippable must be in an if-statement Init position: "+
						"`if op := ClassifySkippable(...); op != nil { ... }`. "+
						"A bare call risks nil-deref on *op when the error is not skippable.", pos))
			}
			return true
		})
	}

	for _, v := range violations {
		t.Error(v)
	}
}

// TestExactlyOneClassifyPerAWSError performs interprocedural taint analysis
// across the entire enumeration package to verify that no AWS SDK error is
// classified by ClassifySkippable more than once along any error propagation
// path. (The "at least once" property is enforced by
// TestAWSClientErrorsMustBeClassifiedOrReturned.)
//
// The analysis has three phases:
//
//  1. Intra-function: run checkAWSErrorHandling on every function to compute
//     per-function taint results. This handles closures, AWS SDK calls, and
//     ClassifySkippable within a single function.
//
//  2. Interprocedural fixpoint: propagate "alreadyClassified" taint through
//     the call graph. If function B classifies an error AND returns it
//     (leaks), and function A calls B and captures err, A receives
//     alreadyClassified taint. If A also doesn't classify (just returns err),
//     A becomes a leaker too. Iterate until stable.
//
//  3. Violation detection: any function that calls ClassifySkippable AND
//     calls a function that leaks alreadyClassified taint is
//     double-classifying. The violation is reported at the caller that
//     re-classifies, not at the leaker (the leaker is doing nothing wrong
//     — it classified and returned, which is legitimate).
func TestExactlyOneClassifyPerAWSError(t *testing.T) {
	enumDir := filepath.Join(findRepoRoot(t), "pkg", "aws", "enumeration")
	fset := token.NewFileSet()
	var violations []string

	entries, err := os.ReadDir(enumDir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}

	// Parse all non-test files.
	type parsedFile struct {
		file       *ast.File
		awsAliases map[string]bool
	}
	var files []parsedFile

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(enumDir, entry.Name())
		f, parseErr := parser.ParseFile(fset, path, nil, 0)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", path, parseErr)
		}
		files = append(files, parsedFile{file: f, awsAliases: collectAWSServiceAliases(f)})
	}

	// Phase 1: Intra-function taint analysis + metadata collection.
	type funcInfo struct {
		name        string
		pos         token.Position
		taint       taintResult
		hasClassify bool
		callees     []string
	}
	funcsByName := make(map[string][]*funcInfo)

	for _, pf := range files {
		ast.Inspect(pf.file, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				return true
			}
			info := &funcInfo{
				name: fn.Name.Name,
				pos:  fset.Position(fn.Pos()),
			}
			ast.Inspect(fn.Body, func(inner ast.Node) bool {
				call, ok := inner.(*ast.CallExpr)
				if !ok {
					return true
				}
				if nameMatches(call.Fun, "ClassifySkippable") {
					info.hasClassify = true
				}
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
					info.callees = append(info.callees, sel.Sel.Name)
				}
				if ident, ok := call.Fun.(*ast.Ident); ok {
					info.callees = append(info.callees, ident.Name)
				}
				return true
			})
			awsVars := findAWSVarsInFunc(fn.Body, pf.awsAliases)
			info.taint = checkAWSErrorHandling(fset, fn.Body.List, pf.awsAliases, awsVars, &violations)
			funcsByName[info.name] = append(funcsByName[info.name], info)
			return true
		})
	}

	// Phase 2: Interprocedural fixpoint — propagate alreadyClassified taint.
	// A name leaks if ANY implementation leaks (worst-case for collisions).
	leaksClassified := make(map[string]bool)
	for name, impls := range funcsByName {
		for _, impl := range impls {
			if impl.taint.alreadyClassified {
				leaksClassified[name] = true
			}
		}
	}
	// Fixpoint: if A calls leaker B and A doesn't classify (just propagates),
	// A also leaks. Repeat through any number of intermediate layers.
	for changed := true; changed; {
		changed = false
		for name, impls := range funcsByName {
			if leaksClassified[name] {
				continue
			}
			for _, impl := range impls {
				if impl.hasClassify {
					continue // classifiers are checked in Phase 3, not propagated
				}
				for _, callee := range impl.callees {
					if leaksClassified[callee] {
						leaksClassified[name] = true
						changed = true
					}
				}
			}
		}
	}

	// Compute transitive classifiers: a function is a classifier if it
	// calls ClassifySkippable directly OR calls another classifier.
	classifies := make(map[string]bool)
	for _, impls := range funcsByName {
		for _, impl := range impls {
			if impl.hasClassify {
				classifies[impl.name] = true
			}
		}
	}
	for changed := true; changed; {
		changed = false
		for _, impls := range funcsByName {
			for _, impl := range impls {
				if classifies[impl.name] {
					continue
				}
				for _, callee := range impl.callees {
					if classifies[callee] {
						classifies[impl.name] = true
						changed = true
					}
				}
			}
		}
	}

	// Phase 3: Detect double classification.
	// Two cases:
	// (a) A function that directly classifies AND calls a leaker.
	// (b) A function that calls a leaker AND calls a (transitive) classifier,
	//     routing the already-classified error to another ClassifySkippable.
	for _, impls := range funcsByName {
		for _, impl := range impls {
			callsLeaker := ""
			callsClassifier := ""
			for _, callee := range impl.callees {
				if leaksClassified[callee] && callsLeaker == "" {
					callsLeaker = callee
				}
				if classifies[callee] && callsClassifier == "" {
					callsClassifier = callee
				}
			}
			// Also check if the function itself classifies.
			if impl.hasClassify && callsLeaker != "" {
				callsClassifier = impl.name + " (self)"
			}
			if callsLeaker != "" && callsClassifier != "" {
				violations = append(violations, fmt.Sprintf(
					"%s: %s receives an already-classified error from %s and routes "+
						"it to %s which also calls ClassifySkippable — the same error "+
						"will be recorded in SkipReport twice. Ensure only one level "+
						"in the call chain classifies each error.",
					impl.pos, impl.name, callsLeaker, callsClassifier))
			}
		}
	}

	for _, v := range violations {
		t.Error(v)
	}
}


// TestAWSClientErrorsMustBeClassifiedOrReturned is a static-analysis test that
// ensures every error returned from an AWS SDK client method call is either
// routed through ClassifySkippable or propagated via a return statement.
//
// It detects AWS SDK clients by tracing import paths: any package under
// github.com/aws/aws-sdk-go-v2/service/ is an AWS service SDK. Variables
// assigned from <sdk>.NewFromConfig() are AWS clients; variables assigned
// from <sdk>.New*Paginator() are AWS paginators. Method calls on these
// variables that capture an error must handle it properly.
//
// This catches the pre-existing bug class where an AWS API error is logged
// and swallowed (slog.Warn + continue) instead of flowing through the
// SkipReport, causing silent data loss.
func TestAWSClientErrorsMustBeClassifiedOrReturned(t *testing.T) {
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

		// Only check files that have a skipReport field (enumerator files).
		if !fileHasSkipReportField(f) {
			continue
		}

		// Step 1: collect import aliases for AWS SDK service packages.
		awsAliases := collectAWSServiceAliases(f)
		if len(awsAliases) == 0 {
			continue
		}

		// Step 2: walk each function, track AWS client/paginator variables,
		// then check error handling for their method calls.
		ast.Inspect(f, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				return true
			}

			// Find AWS client and paginator variables in this function.
			awsVars := findAWSVarsInFunc(fn.Body, awsAliases)

			// Taint analysis: trace AWS SDK errors through the function.
			taint := checkAWSErrorHandling(fset, fn.Body.List, awsAliases, awsVars, &violations)

			// Exported methods that let unclassified AWS errors escape.
			if taint.needsClassification && fn.Name.IsExported() {
				pos := fset.Position(fn.Pos())
				violations = append(violations, fmt.Sprintf(
					"%s: %s returns AWS SDK errors without calling ClassifySkippable — "+
						"error taint escapes the method. Add ClassifySkippable in the error handling path "+
						"so the SkipReport captures the error before it propagates.", pos, fn.Name.Name))
			}
			return true
		})
	}

	for _, v := range violations {
		t.Error(v)
	}
}

// collectAWSServiceAliases returns the set of local import names for direct
// AWS SDK service packages (github.com/aws/aws-sdk-go-v2/service/<svc>).
// Sub-packages like service/ec2/types are excluded — they contain type
// definitions, not client constructors.
func collectAWSServiceAliases(f *ast.File) map[string]bool {
	const prefix = "github.com/aws/aws-sdk-go-v2/service/"
	aliases := make(map[string]bool)
	for _, imp := range f.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		if !strings.HasPrefix(path, prefix) {
			continue
		}
		// Only match direct service packages (one component after "service/").
		suffix := path[len(prefix):]
		if strings.Contains(suffix, "/") {
			continue
		}
		var localName string
		if imp.Name != nil {
			localName = imp.Name.Name
		} else {
			localName = suffix
		}
		aliases[localName] = true
	}
	return aliases
}

// findAWSVarsInFunc performs a simple intra-function dataflow analysis to find
// all variable names that are transitively derived from AWS SDK calls.
//
// A variable is an "AWS variable" if it is assigned from:
//   - A direct package-level call: <awsAlias>.Anything(...) (e.g. ec2.NewFromConfig, ssm.NewListDocumentsPaginator)
//   - A method call on another AWS variable: awsVar.Method(...) (e.g. client.ListApps, paginator.NextPage)
//
// This propagates through the function body until no new AWS vars are discovered.
func findAWSVarsInFunc(body *ast.BlockStmt, awsAliases map[string]bool) map[string]bool {
	vars := make(map[string]bool)

	// Iterate to fixpoint: each pass may discover new AWS vars from method
	// calls on previously-discovered vars.
	for {
		changed := false
		ast.Inspect(body, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for _, rhs := range assign.Rhs {
				call, ok := rhs.(*ast.CallExpr)
				if !ok {
					continue
				}
				if !isAWSCall(call, awsAliases, vars) {
					continue
				}
				for _, lhs := range assign.Lhs {
					if ident, ok := lhs.(*ast.Ident); ok && ident.Name != "_" && ident.Name != "err" {
						if !vars[ident.Name] {
							vars[ident.Name] = true
							changed = true
						}
					}
				}
			}
			return true
		})
		if !changed {
			break
		}
	}
	return vars
}

// isAWSCall returns true if the call expression is either:
//   - <awsAlias>.Anything(...) — a direct SDK package call
//   - <awsVar>.Method(...)   — a method call on a known AWS variable
func isAWSCall(call *ast.CallExpr, awsAliases, awsVars map[string]bool) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	return awsAliases[ident.Name] || awsVars[ident.Name]
}

// taintResult describes how AWS SDK error taint flows out of a scope.
type taintResult struct {
	needsClassification bool // error returned without ClassifySkippable — caller must classify
	alreadyClassified   bool // error returned AFTER ClassifySkippable — caller must NOT classify again
}

// checkAWSErrorHandling performs intra-function taint analysis: it marks
// errors originating from AWS SDK calls as "tainted" and traces them through
// the function until they reach ClassifySkippable (resolved) or are silently
// dropped (violation).
//
// The analysis is architecture-independent — it does not assume any specific
// error handling pattern, dispatcher, or closure structure. It traces error
// flow through assignments and returns:
//
//   - An AWS SDK call that captures `err` taints that variable.
//   - A call whose closure argument contains a tainted-and-returned error
//     also taints the caller's `err`.
//   - A tainted `err` in an `if err != nil` block is resolved if that block
//     calls ClassifySkippable — but if the same block ALSO returns err, the
//     taint becomes "already classified" (must not be classified again).
//   - A tainted `err` that is returned without classification propagates as
//     "needs classification."
//   - A tainted `err` that is neither classified nor returned is a violation
//     (silently dropped).
//
// The returned taintResult tells the caller what kind of taint escapes:
//   - needsClassification: caller should classify (at least once)
//   - alreadyClassified: caller must NOT classify again (at most once)
func checkAWSErrorHandling(fset *token.FileSet, stmts []ast.Stmt, awsAliases, awsVars map[string]bool, violations *[]string) taintResult {
	result := taintResult{}

	for i, stmt := range stmts {
		// Recurse into non-closure nested blocks (for-loops, if-bodies, etc.).
		for _, nested := range collectNestedStmtListsNoClosure(stmt) {
			inner := checkAWSErrorHandling(fset, nested, awsAliases, awsVars, violations)
			if inner.needsClassification {
				result.needsClassification = true
			}
			if inner.alreadyClassified {
				result.alreadyClassified = true
			}
		}

		// Check return statements that contain calls with tainted closures.
		// e.g., `return paginator.Paginate(func() { ... AWS call ... })`
		if ret, ok := stmt.(*ast.ReturnStmt); ok {
			for _, retExpr := range ret.Results {
				call, ok := retExpr.(*ast.CallExpr)
				if !ok {
					continue
				}
				for _, arg := range call.Args {
					fl, ok := arg.(*ast.FuncLit)
					if !ok || fl.Body == nil {
						continue
					}
					inner := checkAWSErrorHandling(fset, fl.Body.List, awsAliases, awsVars, violations)
					if inner.needsClassification {
						result.needsClassification = true
					}
					if inner.alreadyClassified {
						result.alreadyClassified = true
					}
				}
			}
		}

		// Look for assignments that capture err.
		assign, ok := stmt.(*ast.AssignStmt)
		if !ok {
			continue
		}
		if !assignCapturesErr(assign) {
			continue
		}

		// Determine if this assignment taints err:
		// (a) direct AWS SDK call,
		// (b) a call whose closure returns unclassified AWS errors, or
		// (c) a call whose closure returns already-classified AWS errors.
		tainted := false
		alreadyClassifiedTaint := false
		callPos := token.NoPos

		for _, rhs := range assign.Rhs {
			call, ok := rhs.(*ast.CallExpr)
			if !ok {
				continue
			}

			// Check closures in call arguments.
			for _, arg := range call.Args {
				fl, ok := arg.(*ast.FuncLit)
				if !ok || fl.Body == nil {
					continue
				}
				inner := checkAWSErrorHandling(fset, fl.Body.List, awsAliases, awsVars, violations)
				if inner.needsClassification {
					tainted = true
					callPos = call.Pos()
				}
				if inner.alreadyClassified {
					tainted = true
					alreadyClassifiedTaint = true
					callPos = call.Pos()
				}
			}

			// Direct AWS SDK call.
			if isAWSCall(call, awsAliases, awsVars) {
				tainted = true
				callPos = call.Pos()
			}
		}

		if !tainted {
			continue
		}

		// err is tainted. Find the if-err-nil check.
		ifStmt := findNextIfErrNil(stmts[i+1:])
		if ifStmt == nil {
			pos := fset.Position(callPos)
			*violations = append(*violations, fmt.Sprintf(
				"%s: AWS SDK error captured but no if-err-nil check follows", pos))
			continue
		}

		hasClassify := ifBodyHasClassify(ifStmt.Body)
		returnsErr := ifBodyReturnsErr(ifStmt.Body)

		// Double-classification: error was already classified in a callee/closure,
		// and this level classifies it again.
		if alreadyClassifiedTaint && hasClassify {
			pos := fset.Position(callPos)
			*violations = append(*violations, fmt.Sprintf(
				"%s: AWS SDK error was already classified by ClassifySkippable in a callee "+
					"but this level classifies it again — the same error will be recorded "+
					"in SkipReport twice. Remove ClassifySkippable at this level or ensure "+
					"the callee does not return the error after classifying.", pos))
			continue
		}

		// Classified at this level. The standard pattern is:
		//   if op := ClassifySkippable(...); op != nil { record; return nil }
		//   return fmt.Errorf("...: %w", err)
		//
		// The if-body has both ClassifySkippable (for skippable errors) and
		// return-err (for non-skippable errors). This is fully resolved:
		// - Skippable errors → classified and swallowed
		// - Non-skippable errors → propagated (they DON'T need classification)
		//
		// The only case where classified taint escapes is if the ClassifySkippable
		// block itself returns err (not nil) — meaning the SAME classified error
		// is also propagated. We detect this by checking if any return inside
		// the ClassifySkippable if-block (not the outer if-err-nil) returns err.
		if hasClassify {
			if classifyBlockReturnsErr(ifStmt.Body) {
				result.alreadyClassified = true
			}
			// else: standard pattern — fully resolved, no taint escapes.
			continue
		}

		// Returned without classification — taint propagates.
		if returnsErr {
			if alreadyClassifiedTaint {
				result.alreadyClassified = true
			} else {
				result.needsClassification = true
			}
			continue
		}

		// Neither classified nor returned — silently dropped.
		pos := fset.Position(callPos)
		*violations = append(*violations, fmt.Sprintf(
			"%s: AWS SDK error is handled without ClassifySkippable and not returned — "+
				"error is silently dropped. Either classify via ClassifySkippable or propagate via return.", pos))
	}

	return result
}

// classifyBlockReturnsErr checks whether any ClassifySkippable if-block
// within the given body returns err. This detects the pattern:
//
//	if op := ClassifySkippable(err, ...); op != nil {
//	    record(op)
//	    return err  // ← this is the problem: classified AND leaked
//	}
//
// The standard safe pattern returns nil (not err) after classifying.
func classifyBlockReturnsErr(outerBody *ast.BlockStmt) bool {
	found := false
	ast.Inspect(outerBody, func(n ast.Node) bool {
		if found {
			return false
		}
		ifStmt, ok := n.(*ast.IfStmt)
		if !ok || ifStmt.Init == nil || ifStmt.Body == nil {
			return true
		}
		assign, ok := ifStmt.Init.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 {
			return true
		}
		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if !ok || !nameMatches(call.Fun, "ClassifySkippable") {
			return true
		}
		// This is a ClassifySkippable if-block. Check if its body returns err.
		if ifBodyReturnsErr(ifStmt.Body) {
			found = true
		}
		return !found
	})
	return found
}

// assignCapturesErr returns true if any LHS identifier is named "err".
func assignCapturesErr(assign *ast.AssignStmt) bool {
	for _, lhs := range assign.Lhs {
		if ident, ok := lhs.(*ast.Ident); ok && ident.Name == "err" {
			return true
		}
	}
	return false
}

// collectNestedStmtListsNoClosure extracts child statement lists from a
// statement node, EXCLUDING closures (FuncLit). Closures are handled
// separately in checkAWSErrorHandling because their errors flow to the
// enclosing call expression, not to the current scope.
func collectNestedStmtListsNoClosure(stmt ast.Stmt) [][]ast.Stmt {
	var lists [][]ast.Stmt
	ast.Inspect(stmt, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.FuncLit:
			return false // closures handled separately
		case *ast.ForStmt:
			if s.Body != nil {
				lists = append(lists, s.Body.List)
			}
			return false
		case *ast.RangeStmt:
			if s.Body != nil {
				lists = append(lists, s.Body.List)
			}
			return false
		case *ast.IfStmt:
			if s.Body != nil {
				lists = append(lists, s.Body.List)
			}
			if s.Else != nil {
				if block, ok := s.Else.(*ast.BlockStmt); ok {
					lists = append(lists, block.List)
				}
			}
			return false
		case *ast.SwitchStmt:
			if s.Body != nil {
				for _, clause := range s.Body.List {
					if cc, ok := clause.(*ast.CaseClause); ok {
						lists = append(lists, cc.Body)
					}
				}
			}
			return false
		case *ast.SelectStmt:
			if s.Body != nil {
				for _, clause := range s.Body.List {
					if cc, ok := clause.(*ast.CommClause); ok {
						lists = append(lists, cc.Body)
					}
				}
			}
			return false
		}
		return true
	})
	return lists
}

// findNextIfErrNil returns the first `if err != nil` statement in the
// given statement list, or nil if not found. Skips non-if statements.
func findNextIfErrNil(stmts []ast.Stmt) *ast.IfStmt {
	for _, s := range stmts {
		ifStmt, ok := s.(*ast.IfStmt)
		if !ok {
			continue
		}
		if isErrNilCheck(ifStmt.Cond) {
			return ifStmt
		}
		// First non-matching statement — stop looking.
		return nil
	}
	return nil
}

// isErrNilCheck returns true if the expression is `err != nil`.
func isErrNilCheck(expr ast.Expr) bool {
	bin, ok := expr.(*ast.BinaryExpr)
	if !ok || bin.Op.String() != "!=" {
		return false
	}
	lIdent, lOk := bin.X.(*ast.Ident)
	rIdent, rOk := bin.Y.(*ast.Ident)
	return lOk && rOk && lIdent.Name == "err" && rIdent.Name == "nil"
}

// ifBodyHasClassify returns true if the if-body calls ClassifySkippable.
func ifBodyHasClassify(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		if call, ok := n.(*ast.CallExpr); ok && nameMatches(call.Fun, "ClassifySkippable") {
			found = true
		}
		return !found
	})
	return found
}

// ifBodyReturnsErr returns true if the if-body contains a return statement
// that references the err variable.
func ifBodyReturnsErr(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		if ret, ok := n.(*ast.ReturnStmt); ok {
			for _, result := range ret.Results {
				if containsIdent(result, "err") {
					found = true
				}
			}
		}
		return !found
	})
	return found
}

// containsIdent checks whether the expression tree contains an identifier
// with the given name (e.g. "err" inside fmt.Errorf("...: %w", err)).
func containsIdent(expr ast.Expr, name string) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if found {
			return false
		}
		if ident, ok := n.(*ast.Ident); ok && ident.Name == name {
			found = true
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
