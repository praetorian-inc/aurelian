// Package conventions holds repo-wide convention checks that run under the
// normal (non-integration) `go test` pass so they gate every PR in CI.
//
// The integration build tag is deliberately NOT set on this file: it loads and
// type-checks OTHER packages (under the integration tag) via go/packages rather
// than being compiled with them, so it must run in the default build that CI
// exercises. It needs no cloud credentials — nothing here executes a test, it
// only inspects type information.
package conventions_test

import (
	"go/ast"
	"go/types"
	"sort"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

const (
	modulePath      = "github.com/praetorian-inc/aurelian"
	fixturePkgPath  = modulePath + "/test/testutil/fixture"
	fixtureIface    = "Fixture" // fixture.Fixture — implemented by every deployed fixture
	baseFixtureType = "BaseFixture"
	runTestsFunc    = "RunTests" // fixture.RunTests — the end-of-package drain
)

// TestIntegrationFixturePackagesDrainViaRunTests enforces the fixture-cleanup
// contract introduced in the "destroy fixtures on package success" change:
// every package whose tests deploy fixtures MUST own a TestMain that calls
// fixture.RunTests, otherwise its fixtures leak (idle cloud cost) because the
// end-of-package destroy never fires.
//
// This is a TYPE-AWARE backstop. Rather than matching constructor names, it
// loads every package under the integration build tag with full type info and:
//
//   - flags a package as fixture-deploying if any of its test files call a
//     function whose result implements fixture.Fixture (or is *fixture.BaseFixture).
//     This catches existing constructors (testutil.New{,AWS,Azure,GCP}Fixture)
//     AND any future one, by type — no name list to keep in sync.
//   - confirms drainage by resolving each call's callee to a function and
//     checking it is RunTests declared in the fixture package, so a same-named
//     helper in any other package can never spoof it.
//
// Adding a new integration-test package that deploys fixtures but forgets the
// TestMain compiles and passes today; this test turns that omission into a CI
// failure with a copy-pasteable fix.
func TestIntegrationFixturePackagesDrainViaRunTests(t *testing.T) {
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
			packages.NeedTypes | packages.NeedTypesInfo | packages.NeedDeps | packages.NeedImports,
		BuildFlags: []string{"-tags=integration"},
		Tests:      true, // load *_test.go and the synthesized test variants
	}

	pkgs, err := packages.Load(cfg, modulePath+"/...")
	if err != nil {
		t.Fatalf("loading packages: %v", err)
	}

	// Aggregate per logical package (group the [X], [X.test], X_test variants
	// that go/packages emits for one directory under one key).
	type pkgFacts struct {
		name           string // import path of the underlying package, for messages
		deploys        bool
		drains         bool
		sampleDeployer string // a function whose call deploys a fixture, for the message
	}
	facts := map[string]*pkgFacts{}
	keyOf := func(p *packages.Package) string {
		// Collapse "pkg.test", "pkg [pkg.test]", "pkg_test [pkg.test]" to "pkg".
		k := p.PkgPath
		k = strings.TrimSuffix(k, ".test")
		k = strings.TrimSuffix(k, "_test")
		return k
	}

	var loadErr bool
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		for _, e := range p.Errors {
			// A type-check error in an unrelated package shouldn't silently
			// weaken the check — surface it and fail.
			t.Errorf("package %s: %v", p.PkgPath, e)
			loadErr = true
		}
	})
	if loadErr {
		t.FailNow()
	}

	for _, p := range pkgs {
		// Only consider packages that actually carry test syntax + type info.
		if p.TypesInfo == nil || len(p.Syntax) == 0 {
			continue
		}
		// Skip the fixture package itself and the testutil helpers: the former
		// owns the lifecycle (and its own TestMain), the latter only defines the
		// constructors (it deploys nothing at test time).
		base := keyOf(p)
		if base == fixturePkgPath || base == modulePath+"/test/testutil" {
			continue
		}

		f := facts[base]
		if f == nil {
			f = &pkgFacts{name: base}
			facts[base] = f
		}

		for _, file := range p.Syntax {
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				// Drain detection: does this call resolve to fixture.RunTests?
				// Matched by (package path, name) rather than pointer identity,
				// because go/packages type-checks the fixture package once per
				// importing variant — pointer identity does not survive that.
				if obj := calleeObject(p.TypesInfo, call); isFixtureObj(obj, runTestsFunc) {
					f.drains = true
				}
				// Deploy detection: does this call return a fixture.Fixture
				// (or *fixture.BaseFixture)?
				if resultDeploysFixture(p.TypesInfo, call) {
					f.deploys = true
					if f.sampleDeployer == "" {
						f.sampleDeployer = callDescription(p.TypesInfo, call)
					}
				}
				return true
			})
		}
	}

	var offenders []string
	for _, f := range facts {
		if f.deploys && !f.drains {
			line := strings.TrimPrefix(f.name, modulePath+"/")
			if f.sampleDeployer != "" {
				line += " (deploys via " + f.sampleDeployer + ")"
			}
			offenders = append(offenders, line)
		}
	}
	sort.Strings(offenders)

	if len(offenders) > 0 {
		t.Errorf("integration-test packages deploy fixtures but lack a TestMain that drains them:\n  - %s\n\n"+
			"Each listed package must add a file (e.g. testmain_test.go) containing:\n\n"+
			"\t//go:build integration\n\n"+
			"\tpackage <pkg>\n\n"+
			"\timport (\n"+
			"\t\t\"os\"\n"+
			"\t\t\"testing\"\n\n"+
			"\t\t\"%s\"\n"+
			"\t)\n\n"+
			"\tfunc TestMain(m *testing.M) { os.Exit(fixture.RunTests(m)) }\n\n"+
			"Without it, the package's fixtures are never destroyed after a successful run (idle cloud cost).",
			strings.Join(offenders, "\n  - "), fixturePkgPath)
	}
}

// isFixtureObj reports whether obj is the named object `name` declared in the
// fixture package. Matching by (package path, name) is deliberate: go/packages
// type-checks the fixture package once per importing variant, so the same
// logical object appears as distinct *types.Object pointers across packages —
// pointer identity would miss most matches.
func isFixtureObj(obj types.Object, name string) bool {
	if obj == nil || obj.Pkg() == nil {
		return false
	}
	return obj.Pkg().Path() == fixturePkgPath && obj.Name() == name
}

// calleeObject returns the function/var object a call expression resolves to,
// or nil if it can't be determined.
func calleeObject(info *types.Info, call *ast.CallExpr) types.Object {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return info.Uses[fun]
	case *ast.SelectorExpr:
		return info.Uses[fun.Sel]
	}
	return nil
}

// resultDeploysFixture reports whether the call's result type is the
// fixture.Fixture interface or *fixture.BaseFixture — i.e. the call hands back
// a deployable fixture. It walks the result type to its underlying named type
// and matches on (package path, type name), so it is purely type-driven (any
// constructor, any name) and stable across go/packages test variants.
func resultDeploysFixture(info *types.Info, call *ast.CallExpr) bool {
	tv, ok := info.Types[call]
	if !ok || tv.Type == nil {
		return false
	}
	return typeIsFixture(tv.Type)
}

func typeIsFixture(typ types.Type) bool {
	// A *types.Tuple is never aliased; handle it before unaliasing.
	if tup, ok := typ.(*types.Tuple); ok { // multi-return constructor: check each result
		for i := 0; i < tup.Len(); i++ {
			if typeIsFixture(tup.At(i).Type()) {
				return true
			}
		}
		return false
	}
	// Unalias first: constructors that return the testutil.Fixture alias
	// (type Fixture = fixture.Fixture) surface here as *types.Alias.
	switch t := types.Unalias(typ).(type) {
	case *types.Pointer: // *fixture.BaseFixture
		return isFixtureNamed(t.Elem(), baseFixtureType)
	case *types.Named: // fixture.Fixture (interface)
		return isFixtureNamed(t, fixtureIface)
	}
	return false
}

// isFixtureNamed reports whether typ is the named type `name` from the fixture
// package. types.Alias (Go 1.22+, e.g. testutil.Fixture = fixture.Fixture) is
// unwrapped to its target first so the alias matches too.
func isFixtureNamed(typ types.Type, name string) bool {
	named, ok := types.Unalias(typ).(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	if obj == nil || obj.Pkg() == nil {
		return false
	}
	return obj.Pkg().Path() == fixturePkgPath && obj.Name() == name
}

// callDescription renders a human-readable callee name for the failure message,
// e.g. "testutil.NewAzureFixture".
func callDescription(info *types.Info, call *ast.CallExpr) string {
	if obj := calleeObject(info, call); obj != nil {
		if pkg := obj.Pkg(); pkg != nil {
			return pkg.Name() + "." + obj.Name()
		}
		return obj.Name()
	}
	return "a fixture constructor"
}
