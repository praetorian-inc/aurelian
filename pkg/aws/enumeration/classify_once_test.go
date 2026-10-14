package enumeration_test

import (
	"fmt"
	"go/token"
	"go/types"
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/vta"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// TestClassifySkippableExactlyOnce verifies the enumeration resilience
// invariant: every AWS SDK error in every enumerator reaches
// ClassifySkippable exactly once on every execution path.
//
// Why exactly once:
//   - Zero times means an unhandled SDK error can abort the entire pipeline,
//     defeating the enumeration resilience goal (LAB-2525).
//   - More than once means redundant classification — the error handling
//     wiring is ambiguous (which level is responsible?) and risks double-
//     recording in the SkipReport.
//
// Two implementations, automatic fallback:
//   - Z3 (preferred): builds a value-flow graph from SSA, encodes it as
//     SMT-LIB2, and uses the Z3 solver to formally prove the property
//     across all execution paths. Produces counterexample paths on failure.
//   - SSA (fallback): heuristic taint tracing through the SSA value graph.
//     Used when z3 is not installed (e.g. CI).
func TestClassifySkippableExactlyOnce(t *testing.T) {
	if _, err := exec.LookPath("z3"); err == nil {
		t.Log("z3 found — using Z3 solver for formal verification")
		testClassifySkippableExactlyOnce_Z3(t)
		return
	}
	t.Log("z3 not found — falling back to SSA value-flow tracing")
	testClassifySkippableExactlyOnce_SSA(t)
}

func testClassifySkippableExactlyOnce_SSA(t *testing.T) {
	t.Helper()

	cfg := &packages.Config{
		Mode: packages.LoadAllSyntax,
		Dir:  ".",
	}
	pkgs, err := packages.Load(cfg, ".")
	if err != nil {
		t.Fatalf("load package: %v", err)
	}
	if packages.PrintErrors(pkgs) > 0 {
		t.Fatal("package has type errors")
	}

	prog, ssaPkgs := ssautil.Packages(pkgs, ssa.InstantiateGenerics)
	prog.Build()

	if len(ssaPkgs) == 0 || ssaPkgs[0] == nil {
		t.Fatal("failed to build SSA for enumeration package")
	}
	enumPkg := ssaPkgs[0]

	classifyFn := findSSAFunc(enumPkg, "ClassifySkippable")
	if classifyFn == nil {
		t.Fatal("ClassifySkippable not found")
	}

	allFuncs := ssautil.AllFunctions(prog)
	cg := vta.CallGraph(allFuncs, nil)

	ourFuncs := collectPackageFuncs(prog, enumPkg)

	var violations []string
	awsCallCount := 0
	for _, fn := range ourFuncs {
		if fn.Blocks == nil {
			continue
		}
		// Skip deliberate bug patterns from the stress enumerator.
		if isStressBugFunc(fn) {
			continue
		}
		checkFunctionExactlyOnce(fn, classifyFn, cg, prog.Fset, &violations)
		for _, block := range fn.Blocks {
			for _, instr := range block.Instrs {
				if call, ok := instr.(*ssa.Call); ok && isAWSSDKCall(call) {
					awsCallCount++
				}
			}
		}
	}
	t.Logf("Analyzed %d AWS SDK call sites across %d functions", awsCallCount, len(ourFuncs))

	for _, v := range violations {
		t.Error(v)
	}
}

// isStressBugFunc returns true if fn or its parent is a deliberate bug pattern
// (stressBug_ prefix) from the stress enumerator.
func isStressBugFunc(fn *ssa.Function) bool {
	for _, name := range []string{fn.Name(), ssaParentName(fn)} {
		if strings.HasPrefix(name, "stressBug_") {
			return true
		}
	}
	return false
}

func ssaParentName(fn *ssa.Function) string {
	if p := fn.Parent(); p != nil {
		return p.Name()
	}
	return ""
}

// --- Per-function analysis ---

func checkFunctionExactlyOnce(fn *ssa.Function, classifyFn *ssa.Function, cg *callgraph.Graph, fset *token.FileSet, violations *[]string) {
	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			call, ok := instr.(*ssa.Call)
			if !ok || !isAWSSDKCall(call) {
				continue
			}
			errVal := extractErrorFromCall(call)
			if errVal == nil {
				continue
			}

			count := countClassifyOnErrorPath(errVal, classifyFn, cg, make(map[ssa.Value]bool))
			pos := fset.Position(call.Pos())

			if count == 0 {
				// Check if the error is silently dropped (only used in
				// BinOp comparison, never passed to a function or returned).
				if errorIsSilentlyDropped(errVal) {
					*violations = append(*violations, fmt.Sprintf(
						"%s: AWS SDK error from %s is silently dropped "+
							"(handled without ClassifySkippable, error not propagated)",
						pos, describeSSACall(call)))
				}
				// If the error IS used (returned/passed), count==0 means
				// the trace couldn't follow it to ClassifySkippable. This
				// could be a real issue or a trace limitation. Flag it.
				*violations = append(*violations, fmt.Sprintf(
					"%s: AWS SDK error from %s never reaches ClassifySkippable",
					pos, describeSSACall(call)))
			} else if count > 1 {
				*violations = append(*violations, fmt.Sprintf(
					"%s: AWS SDK error from %s reaches ClassifySkippable %d times "+
						"(double recording). Ensure exactly one level classifies each error.",
					pos, describeSSACall(call), count))
			}

			// Per-caller check: if the error flows through Returns to
			// callers, verify EVERY caller classifies it. MAX gives the
			// best-case count, but if any individual caller drops the
			// error, that's a separate violation.
			checkPerCallerDrops(errVal, classifyFn, cg, fset, violations, describeSSACall(call))
		}
	}
	for _, anon := range fn.AnonFuncs {
		checkFunctionExactlyOnce(anon, classifyFn, cg, fset, violations)
	}
}

// checkPerCallerDrops verifies that EVERY call site of the function
// containing the AWS SDK call handles the error correctly. Uses VTA to
// find callers of the enclosing function (and transitive callers up the
// chain), then checks each independently with a fresh visited map.
func checkPerCallerDrops(val ssa.Value, classifyFn *ssa.Function, cg *callgraph.Graph, fset *token.FileSet, violations *[]string, awsCallDesc string) {
	instr, ok := val.(ssa.Instruction)
	if !ok {
		return
	}
	// Walk up the function chain: the AWS SDK call is in fn. If fn
	// returns an error (any error), check each caller of fn.
	fn := instr.Parent()
	checkCallersRecursive(fn, classifyFn, cg, fset, violations, awsCallDesc, make(map[*ssa.Function]bool))
}

// checkCallersRecursive checks each VTA caller of fn. For each caller
// that receives an error from fn, it verifies the error reaches
// ClassifySkippable. If not, reports a violation. Then recurses into
// callers-of-callers for functions that propagate the error.
func checkCallersRecursive(fn *ssa.Function, classifyFn *ssa.Function, cg *callgraph.Graph, fset *token.FileSet, violations *[]string, awsCallDesc string, visited map[*ssa.Function]bool) {
	if visited[fn] {
		return
	}
	visited[fn] = true

	node := cg.Nodes[fn]
	if node == nil {
		return
	}

	// Find which return index is the error.
	sig := fn.Signature
	results := sig.Results()
	errIdx := -1
	for i := 0; i < results.Len(); i++ {
		if isErrorType(results.At(i).Type()) {
			errIdx = i
			break
		}
	}
	if errIdx < 0 {
		return // function doesn't return an error
	}

	for _, edge := range node.In {
		call, ok := edge.Site.(*ssa.Call)
		if !ok || call == nil {
			continue
		}
		errAtCaller := extractReturnedError(call, errIdx)
		if errAtCaller == nil {
			continue
		}

		// Only flag as "dropped" if the caller actively drops the error
		// (doesn't return it, doesn't pass it to any function).
		// If the caller propagates the error (returns it, passes to
		// another function), it's not a drop — the error may reach
		// ClassifySkippable at a higher level.
		if errorIsSilentlyDropped(errAtCaller) {
			pos := fset.Position(call.Pos())
			*violations = append(*violations, fmt.Sprintf(
				"%s: AWS SDK error from %s is dropped at this call site "+
					"(error returned by %s but silently discarded here)",
				pos, awsCallDesc, fn.Name()))
		}
	}

	// Also recurse into callers that propagate the error further up.
	for _, edge := range node.In {
		callerFn := edge.Caller.Func
		if callerFn != nil {
			checkCallersRecursive(callerFn, classifyFn, cg, fset, violations, awsCallDesc, visited)
		}
	}
}

// --- Pure value-flow taint tracing ---

// countClassifyOnErrorPath traces an error value through the SSA value graph
// and counts how many times it reaches ClassifySkippable as the first
// argument. Uses pure value-flow: follows the actual error value through
// Call, Return, Phi, ChangeInterface (fmt.Errorf wrapping), etc.
//
// This naturally handles path-sensitivity for the nil case: if a function
// returns nil instead of err, the nil constant is a different ssa.Value
// that doesn't connect back to the original error.
func countClassifyOnErrorPath(val ssa.Value, classifyFn *ssa.Function, cg *callgraph.Graph, visited map[ssa.Value]bool) int {
	if visited[val] {
		return 0
	}
	visited[val] = true

	refs := val.Referrers()
	if refs == nil {
		return 0
	}

	// Separate referrers into two groups:
	// 1. Direct ClassifySkippable call (the "classify" path)
	// 2. Everything else: Return, ChangeInterface (wrapping), Phi, etc.
	//    (the "propagate" path)
	//
	// In the standard pattern:
	//   if op := ClassifySkippable(err, ...); op != nil {
	//       return nil  ← classify path
	//   }
	//   return fmt.Errorf("...: %w", err)  ← propagate path
	//
	// The classify path and propagate path are MUTUALLY EXCLUSIVE at runtime.
	// We take MAX of the two.
	//
	// Within the propagate path, if the error is returned (Return referrer)
	// AND also wrapped (ChangeInterface → fmt.Errorf → Return), these are
	// the same runtime path — take MAX (not sum, since they're the same
	// error flowing through different SSA nodes to the same Return).
	//
	// If the classify path returns the original error (not nil), that's
	// cumulative: classify here + classify at caller. This is detected
	// because the Return referrer contains the original val (not nil).

	classifyCount := 0
	propagateCount := 0
	returnFnSeen := make(map[*ssa.Function]bool)

	for _, instr := range *refs {
		switch v := instr.(type) {
		case *ssa.Call:
			if v.Common().StaticCallee() == classifyFn {
				if len(v.Common().Args) > 0 && v.Common().Args[0] == val {
					classifyCount++
				}
			} else if callee := v.Common().StaticCallee(); callee != nil {
				c := traceIntoCallee(val, v, callee, classifyFn, cg, visited)
				propagateCount += c
			} else if isValArgOfCall(val, v) {
				// Value passed to a builtin (append) or dynamic call.
				// The call result carries the taint — trace through it.
				// This handles: append(slice, err) → slice carries err's taint.
				c := countClassifyOnErrorPath(v, classifyFn, cg, visited)
				if c > propagateCount {
					propagateCount = c
				}
			}

		case *ssa.Return:
			fn := v.Parent()
			if returnFnSeen[fn] {
				continue
			}
			for i, result := range v.Results {
				if result == val {
					returnFnSeen[fn] = true
					c := traceReturnToCallers(fn, i, classifyFn, cg, visited)
					cc := traceClosureReturn(fn, i, classifyFn, cg, visited)
					if cc > c {
						c = cc
					}
					if c > propagateCount {
						propagateCount = c
					}
				}
			}

		case *ssa.Phi:
			c := countClassifyOnErrorPath(v, classifyFn, cg, visited)
			if c > propagateCount {
				propagateCount = c
			}

		case *ssa.ChangeInterface:
			c := traceChangeInterface(v, classifyFn, cg, visited)
			if c > propagateCount {
				propagateCount = c
			}

		case *ssa.MakeInterface:
			c := countClassifyOnErrorPath(v, classifyFn, cg, visited)
			if c > propagateCount {
				propagateCount = c
			}

		case *ssa.Store:
			c := traceFromStore(v.Addr, classifyFn, cg, visited)
			if c > propagateCount {
				propagateCount = c
			}

		case *ssa.IndexAddr:
			// Slice/array element access. The indexed element carries the
			// taint. Trace loads from this address.
			c := traceFromStore(v, classifyFn, cg, visited)
			if c > propagateCount {
				propagateCount = c
			}

		case *ssa.BinOp:
			continue
		}
	}

	// Determine if classify and propagate are on the same runtime path
	// (cumulative → SUM) or mutually exclusive branches (→ MAX).
	//
	// Use SSA block structure: if the ClassifySkippable call and the
	// propagate instructions are in SIBLING branches of the same If
	// (the ClassifySkippable guard: if op != nil), they're exclusive.
	// Otherwise (same block, no branch, or the error flows to both
	// unconditionally), they're cumulative.
	if classifyCount > 0 {
		if !classifyAndPropagateAreExclusive(val, classifyFn, refs) {
			freshPropagateCount := countPropagateOnly(val, classifyFn, cg)
			if freshPropagateCount > 0 {
				return classifyCount + freshPropagateCount
			}
		}
	}
	if classifyCount > propagateCount {
		return classifyCount
	}
	return propagateCount
}

// countPropagateOnly re-traces the error with a fresh visited map,
// counting ClassifySkippable calls reachable through propagation paths
// (Return, Store, ChangeInterface) while skipping the classification at
// this level. Used when classify and propagate are on the same runtime
// path to detect double-recording.
func countPropagateOnly(val ssa.Value, classifyFn *ssa.Function, cg *callgraph.Graph) int {
	freshVisited := make(map[ssa.Value]bool)
	freshVisited[val] = true

	refs := val.Referrers()
	if refs == nil {
		return 0
	}

	// Trace ONLY propagation referrers (skip ClassifySkippable Call).
	// For each downstream value, use full recursive countClassifyOnErrorPath.
	count := 0
	returnFnSeen := make(map[*ssa.Function]bool)
	for _, instr := range *refs {
		switch v := instr.(type) {
		case *ssa.Call:
			if v.Common().StaticCallee() == classifyFn {
				continue // skip the classification at this level
			}
			if callee := v.Common().StaticCallee(); callee != nil {
				c := traceIntoCallee(val, v, callee, classifyFn, cg, freshVisited)
				if c > count {
					count = c
				}
			} else if isValArgOfCall(val, v) {
				c := countClassifyOnErrorPath(v, classifyFn, cg, freshVisited)
				if c > count {
					count = c
				}
			}
		case *ssa.Return:
			fn := v.Parent()
			if returnFnSeen[fn] {
				continue
			}
			for i, result := range v.Results {
				if result == val {
					returnFnSeen[fn] = true
					c := traceReturnToCallers(fn, i, classifyFn, cg, freshVisited)
					cc := traceClosureReturn(fn, i, classifyFn, cg, freshVisited)
					if cc > c {
						c = cc
					}
					if c > count {
						count = c
					}
				}
			}
		case *ssa.Phi:
			c := countClassifyOnErrorPath(v, classifyFn, cg, freshVisited)
			if c > count {
				count = c
			}
		case *ssa.ChangeInterface:
			c := traceChangeInterface(v, classifyFn, cg, freshVisited)
			if c > count {
				count = c
			}
		case *ssa.MakeInterface:
			c := countClassifyOnErrorPath(v, classifyFn, cg, freshVisited)
			if c > count {
				count = c
			}
		case *ssa.Store:
			c := traceFromStore(v.Addr, classifyFn, cg, freshVisited)
			if c > count {
				count = c
			}
		case *ssa.IndexAddr:
			c := traceFromStore(v, classifyFn, cg, freshVisited)
			if c > count {
				count = c
			}
		case *ssa.BinOp:
			continue
		}
	}
	return count
}

// classifyAndPropagateAreExclusive determines whether the ClassifySkippable
// call and the propagate instructions (Store, Return, ChangeInterface) are
// in mutually exclusive branches of the ClassifySkippable guard.
//
// The standard pattern:
//
//	if op := ClassifySkippable(err, ...); op != nil {
//	    return nil  ← classify path (true-branch)
//	}
//	return fmt.Errorf("...: %w", err)  ← propagate path (after the if = false-branch)
//
// Here, classify and propagate are exclusive — return true.
//
// The bug pattern:
//
//	ClassifySkippable(err, ...)  // no guard, or both in same block
//	append(slice, err)           // propagate in same scope
//
// Here, both execute unconditionally — return false (cumulative).
func classifyAndPropagateAreExclusive(val ssa.Value, classifyFn *ssa.Function, refs *[]ssa.Instruction) bool {
	// Find the ClassifySkippable guard's If instruction.
	var guardIf *ssa.If
	for _, instr := range *refs {
		call, ok := instr.(*ssa.Call)
		if !ok || call.Common().StaticCallee() != classifyFn {
			continue
		}
		// Find the BinOp → If chain from the ClassifySkippable result.
		callRefs := call.Referrers()
		if callRefs == nil {
			continue
		}
		for _, cr := range *callRefs {
			binop, ok := cr.(*ssa.BinOp)
			if !ok {
				continue
			}
			binopRefs := binop.Referrers()
			if binopRefs == nil {
				continue
			}
			for _, br := range *binopRefs {
				if ifInstr, ok := br.(*ssa.If); ok {
					guardIf = ifInstr
					break
				}
			}
			if guardIf != nil {
				break
			}
		}
		if guardIf != nil {
			break
		}
	}

	if guardIf == nil {
		// No If guard around ClassifySkippable — not exclusive.
		return false
	}

	// The guard If has two branches:
	//   Succs[0] = true-branch (op != nil: classified)
	//   Succs[1] = false-branch (op == nil: not classified)
	//
	// For classify and propagate to be exclusive, ALL propagate
	// instructions must be in the false-branch (or its successors),
	// NOT in the true-branch or a common ancestor.
	if len(guardIf.Block().Succs) < 2 {
		return false
	}
	falseBranch := guardIf.Block().Succs[1]

	// Collect all blocks reachable from the false-branch.
	// The true-branch of the guard is where ClassifySkippable's result
	// is used (op != nil). The false-branch is where the error is NOT
	// classified.
	trueBranch := guardIf.Block().Succs[0]

	// Check every propagate referrer. If ANY is NOT exclusively in the
	// false-branch (i.e., it's in the true-branch, the guard block, or
	// a merge block reachable from both), classify and propagate are
	// NOT exclusive.
	for _, instr := range *refs {
		switch instr.(type) {
		case *ssa.BinOp:
			continue
		}
		if call, ok := instr.(*ssa.Call); ok && call.Common().StaticCallee() == classifyFn {
			continue
		}

		block := instr.Block()
		if block == nil {
			continue
		}

		// The referrer must be exclusively in the false-branch path.
		// If it's in the true-branch, or in a merge block reachable from
		// both, it's cumulative with the classify.
		if block == trueBranch {
			return false // explicitly in the classify branch
		}
		if block == guardIf.Block() {
			return false // in the guard block itself (before the branch)
		}
		// Check if the true-branch can reach this block (merge block).
		// But skip the check if this IS the false-branch entry block
		// AND it's not reachable from trueBranch (clean false path).
		if block != falseBranch && reachableFrom(trueBranch, block, make(map[*ssa.BasicBlock]bool)) {
			return false
		}
		if block == falseBranch && reachableFrom(trueBranch, block, make(map[*ssa.BasicBlock]bool)) {
			return false // false-branch IS a merge block
		}
	}

	return true
}

// reachableFrom checks if target is reachable from start following only
// forward edges (no loop back-edges). Back-edges are edges to blocks with
// a lower index, indicating a loop. Excluding them prevents the entire
// loop body from being considered "reachable" from any block in the loop.
func reachableFrom(start, target *ssa.BasicBlock, visited map[*ssa.BasicBlock]bool) bool {
	if start == target {
		return true
	}
	if visited[start] {
		return false
	}
	visited[start] = true
	for _, succ := range start.Succs {
		if succ.Index <= start.Index {
			continue // skip back-edges (loop)
		}
		if reachableFrom(succ, target, visited) {
			return true
		}
	}
	return false
}

// errorIsSilentlyDropped checks if an error value is only used in a BinOp
// comparison (err != nil) and never passed to any function, returned, or
// stored. This detects the pattern:
//
//	if err != nil {
//	    return false, nil  // error dropped, not classified
//	}
func errorIsSilentlyDropped(val ssa.Value) bool {
	refs := val.Referrers()
	if refs == nil {
		return true // no uses at all
	}
	for _, instr := range *refs {
		switch instr.(type) {
		case *ssa.BinOp:
			continue // comparison only — not a meaningful use
		case *ssa.DebugRef:
			continue // debug info — not a meaningful use
		default:
			return false // any other use = not dropped
		}
	}
	return true // only BinOp/DebugRef uses → dropped
}

// --- Interprocedural tracing ---

func traceIntoCallee(errVal ssa.Value, call *ssa.Call, callee *ssa.Function, classifyFn *ssa.Function, cg *callgraph.Graph, visited map[ssa.Value]bool) int {
	if callee.Blocks == nil {
		return 0
	}
	args := call.Common().Args
	for i, arg := range args {
		if arg == errVal && i < len(callee.Params) {
			return countClassifyOnErrorPath(callee.Params[i], classifyFn, cg, visited)
		}
	}
	return 0
}

// traceReturnToCallers traces the returned error to all callers via VTA.
// Returns MAX across callers (each call site is an independent runtime
// invocation). Each caller gets a fresh copy of the visited map so they
// don't pollute each other's traces.
func traceReturnToCallers(fn *ssa.Function, errIdx int, classifyFn *ssa.Function, cg *callgraph.Graph, visited map[ssa.Value]bool) int {
	node := cg.Nodes[fn]

	maxCount := 0
	foundCaller := false
	if node != nil {
		for _, edge := range node.In {
			call, ok := edge.Site.(*ssa.Call)
			if !ok || call == nil {
				continue
			}
			errAtCaller := extractReturnedError(call, errIdx)
			if errAtCaller != nil {
				callerVisited := copyVisited(visited)
				c := countClassifyOnErrorPath(errAtCaller, classifyFn, cg, callerVisited)
				foundCaller = true
				if c > maxCount {
					maxCount = c
				}
			}
		}
	}

	if !foundCaller {
		c := traceClosureReturn(fn, errIdx, classifyFn, cg, visited)
		if c > maxCount {
			maxCount = c
		}
	}

	return maxCount
}

// traceClosureReturn handles closures passed as arguments to external
// functions (e.g., ratelimit.Paginate). VTA can't resolve that Paginate
// calls the closure, so we trace manually: find the MakeClosure in the
// parent function, find the call that receives it, trace the call's error.
func traceClosureReturn(fn *ssa.Function, errIdx int, classifyFn *ssa.Function, cg *callgraph.Graph, visited map[ssa.Value]bool) int {
	parent := fn.Parent()
	if parent == nil || parent.Blocks == nil {
		return 0
	}

	maxCount := 0
	for _, block := range parent.Blocks {
		for _, instr := range block.Instrs {
			mc, ok := instr.(*ssa.MakeClosure)
			if !ok || mc.Fn != fn {
				continue
			}
			if refs := mc.Referrers(); refs != nil {
				for _, ref := range *refs {
					call, ok := ref.(*ssa.Call)
					if !ok {
						continue
					}
					callErrVal := extractErrorFromCall(call)
					if callErrVal != nil {
						c := countClassifyOnErrorPath(callErrVal, classifyFn, cg, visited)
						if c > maxCount {
							maxCount = c
						}
					}
				}
			}
		}
	}
	return maxCount
}

// --- fmt.Errorf wrapping trace ---

// traceChangeInterface traces through the SSA varargs pattern:
// ChangeInterface → Store to array element → Slice → fmt.Errorf Call → result.
func traceChangeInterface(ci *ssa.ChangeInterface, classifyFn *ssa.Function, cg *callgraph.Graph, visited map[ssa.Value]bool) int {
	if visited[ci] {
		return 0
	}
	visited[ci] = true

	refs := ci.Referrers()
	if refs == nil {
		return 0
	}

	count := 0
	for _, instr := range *refs {
		store, ok := instr.(*ssa.Store)
		if !ok {
			continue
		}
		ia, ok := store.Addr.(*ssa.IndexAddr)
		if !ok {
			continue
		}
		alloc, ok := ia.X.(*ssa.Alloc)
		if !ok {
			continue
		}
		c := traceAllocSliceToCall(alloc, classifyFn, cg, visited)
		if c > count {
			count = c
		}
	}
	return count
}

// traceAllocSliceToCall traces from an Alloc (varargs/collection array)
// through Slice → Call → result. Handles both fmt.Errorf varargs and
// append() for collection patterns.
func traceAllocSliceToCall(alloc *ssa.Alloc, classifyFn *ssa.Function, cg *callgraph.Graph, visited map[ssa.Value]bool) int {
	allocRefs := alloc.Referrers()
	if allocRefs == nil {
		return 0
	}
	count := 0
	for _, ar := range *allocRefs {
		sl, ok := ar.(*ssa.Slice)
		if !ok {
			continue
		}
		slRefs := sl.Referrers()
		if slRefs == nil {
			continue
		}
		for _, sr := range *slRefs {
			call, ok := sr.(*ssa.Call)
			if !ok {
				continue
			}
			// Trace the call result. For fmt.Errorf this returns error;
			// for append this returns a slice. Both carry the taint.
			c := countClassifyOnErrorPath(call, classifyFn, cg, visited)
			if c > count {
				count = c
			}
		}
	}
	return count
}

func traceFromStore(addr ssa.Value, classifyFn *ssa.Function, cg *callgraph.Graph, visited map[ssa.Value]bool) int {
	if visited[addr] {
		return 0
	}
	visited[addr] = true

	count := 0

	// Local loads from the same address.
	refs := addr.Referrers()
	if refs != nil {
		for _, instr := range *refs {
			if load, ok := instr.(*ssa.UnOp); ok {
				c := countClassifyOnErrorPath(load, classifyFn, cg, visited)
				if c > count {
					count = c
				}
			}
		}
	}

	// Cross-method field loads: if addr is a FieldAddr, find all loads
	// of the same field on the same struct type across the package.
	if fa, ok := addr.(*ssa.FieldAddr); ok {
		c := traceFieldLoadsAcrossMethods(fa, classifyFn, cg, visited)
		if c > count {
			count = c
		}
	}

	// Varargs/collection array pattern: addr is IndexAddr into an Alloc.
	// The array is sliced and passed to append or fmt.Errorf.
	// Trace: Alloc → Slice → Call → result.
	if ia, ok := addr.(*ssa.IndexAddr); ok {
		if alloc, ok := ia.X.(*ssa.Alloc); ok {
			c := traceAllocSliceToCall(alloc, classifyFn, cg, visited)
			if c > count {
				count = c
			}
		}
	}

	return count
}

// traceFieldLoadsAcrossMethods finds all loads of the same struct field
// across all methods in the package and traces them. This handles the
// sync.Once pattern where a closure stores to s.onceErr and a method
// reads s.onceErr and returns it.
//
// We match on: same struct type (by types.Type identity) + same field index.
func traceFieldLoadsAcrossMethods(storeFA *ssa.FieldAddr, classifyFn *ssa.Function, cg *callgraph.Graph, visited map[ssa.Value]bool) int {
	// Get the struct type and field index from the store's FieldAddr.
	storePtrType := storeFA.X.Type()
	storeFieldIdx := storeFA.Field

	// Search all functions in the program that share the same package.
	fn := storeFA.Parent()
	if fn == nil || fn.Pkg == nil {
		return 0
	}
	pkg := fn.Pkg

	count := 0
	var searchFn func(*ssa.Function)
	searchFn = func(f *ssa.Function) {
		if f.Blocks == nil {
			return
		}
		for _, block := range f.Blocks {
			for _, instr := range block.Instrs {
				// Find FieldAddr instructions for the same field.
				fa, ok := instr.(*ssa.FieldAddr)
				if !ok || fa == storeFA {
					continue
				}
				if fa.Field != storeFieldIdx {
					continue
				}
				// Check if it's the same struct type.
				if !types.Identical(fa.X.Type(), storePtrType) {
					continue
				}
				// Found a matching FieldAddr. Check for loads (UnOp *).
				faRefs := fa.Referrers()
				if faRefs == nil {
					continue
				}
				for _, faRef := range *faRefs {
					if load, ok := faRef.(*ssa.UnOp); ok {
						c := countClassifyOnErrorPath(load, classifyFn, cg, visited)
						if c > count {
							count = c
						}
					}
				}
			}
		}
		for _, anon := range f.AnonFuncs {
			searchFn(anon)
		}
	}

	// Search all package members (functions + methods).
	for _, mem := range pkg.Members {
		switch v := mem.(type) {
		case *ssa.Function:
			searchFn(v)
		case *ssa.Type:
			for _, t := range []types.Type{v.Type(), types.NewPointer(v.Type())} {
				mset := fn.Prog.MethodSets.MethodSet(t)
				for i := 0; i < mset.Len(); i++ {
					if mfn := fn.Prog.MethodValue(mset.At(i)); mfn != nil {
						searchFn(mfn)
					}
				}
			}
		}
	}

	return count
}

// --- Value extraction helpers ---

func extractReturnedError(call *ssa.Call, errIdx int) ssa.Value {
	if refs := call.Referrers(); refs != nil {
		for _, ref := range *refs {
			if ext, ok := ref.(*ssa.Extract); ok && ext.Index == errIdx {
				return ext
			}
		}
	}
	if errIdx == 0 && isErrorType(call.Type()) {
		return call
	}
	return nil
}

func extractErrorFromCall(call *ssa.Call) ssa.Value {
	if isErrorType(call.Type()) {
		return call
	}
	if tup, ok := call.Type().(*types.Tuple); ok {
		for i := 0; i < tup.Len(); i++ {
			if isErrorType(tup.At(i).Type()) {
				return extractReturnedError(call, i)
			}
		}
	}
	return nil
}

func isErrorType(t types.Type) bool {
	return types.Identical(t, types.Universe.Lookup("error").Type())
}

// --- AWS SDK detection ---

const awsServicePrefix = "github.com/aws/aws-sdk-go-v2/service/"

func isAWSSDKCall(call *ssa.Call) bool {
	cc := call.Common()
	if callee := cc.StaticCallee(); callee != nil {
		return isFromAWSServicePkg(callee)
	}
	if cc.IsInvoke() && cc.Method != nil {
		if pkg := cc.Method.Pkg(); pkg != nil {
			return strings.HasPrefix(pkg.Path(), awsServicePrefix)
		}
	}
	return false
}

func isFromAWSServicePkg(fn *ssa.Function) bool {
	if fn.Pkg != nil && fn.Pkg.Pkg != nil {
		if strings.HasPrefix(fn.Pkg.Pkg.Path(), awsServicePrefix) {
			return true
		}
	}
	if recv := fn.Signature.Recv(); recv != nil {
		return typeFromAWSService(recv.Type())
	}
	return false
}

func typeFromAWSService(t types.Type) bool {
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	if named, ok := t.(*types.Named); ok {
		if obj := named.Obj(); obj != nil && obj.Pkg() != nil {
			return strings.HasPrefix(obj.Pkg().Path(), awsServicePrefix)
		}
	}
	return false
}

// --- Misc helpers ---

// isValArgOfCall checks if val is one of the arguments to the call.
func isValArgOfCall(val ssa.Value, call *ssa.Call) bool {
	for _, arg := range call.Common().Args {
		if arg == val {
			return true
		}
	}
	return false
}

func copyVisited(m map[ssa.Value]bool) map[ssa.Value]bool {
	cp := make(map[ssa.Value]bool, len(m))
	for k, v := range m {
		cp[k] = v
	}
	return cp
}

func describeSSACall(call *ssa.Call) string {
	cc := call.Common()
	if callee := cc.StaticCallee(); callee != nil {
		return callee.RelString(nil)
	}
	if cc.IsInvoke() && cc.Method != nil {
		return cc.Method.FullName()
	}
	return call.String()
}

func findSSAFunc(pkg *ssa.Package, name string) *ssa.Function {
	if mem, ok := pkg.Members[name]; ok {
		if fn, ok := mem.(*ssa.Function); ok {
			return fn
		}
	}
	return nil
}

func collectPackageFuncs(prog *ssa.Program, pkg *ssa.Package) []*ssa.Function {
	var result []*ssa.Function
	for _, mem := range pkg.Members {
		switch v := mem.(type) {
		case *ssa.Function:
			result = append(result, v)
		case *ssa.Type:
			for _, t := range []types.Type{v.Type(), types.NewPointer(v.Type())} {
				mset := prog.MethodSets.MethodSet(t)
				for i := 0; i < mset.Len(); i++ {
					if fn := prog.MethodValue(mset.At(i)); fn != nil {
						result = append(result, fn)
					}
				}
			}
		}
	}
	return result
}
