package enumeration_test

import (
	"fmt"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/callgraph/vta"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// nodeKind classifies a node in the value-flow graph.
type nodeKind int

const (
	nkErrorSource nodeKind = iota // AWS SDK call producing an error
	nkClassify                    // ClassifySkippable call consuming an error
	nkBranch                      // SSA If instruction (two successors)
	nkWrap                        // fmt.Errorf wrapping (consumes old, produces new error)
	nkPhi                         // SSA Phi merging errors from predecessors
	nkReturn                      // Function return with non-nil error
	nkReturnNil                   // Function return with *ssa.Const nil error (terminal)
	nkCall                        // Non-classify call receiving an error arg
	nkCallResult                  // Error value extracted from a call's return
	nkExit                        // Top-level return leaving analyzed scope
	nkValueFlow                   // Intermediate SSA value (ChangeInterface, Store, etc.)
)

func (k nodeKind) String() string {
	switch k {
	case nkErrorSource:
		return "ErrorSource"
	case nkClassify:
		return "Classify"
	case nkBranch:
		return "Branch"
	case nkWrap:
		return "Wrap"
	case nkPhi:
		return "Phi"
	case nkReturn:
		return "Return"
	case nkReturnNil:
		return "ReturnNil"
	case nkCall:
		return "Call"
	case nkCallResult:
		return "CallResult"
	case nkExit:
		return "Exit"
	case nkValueFlow:
		return "ValueFlow"
	default:
		return fmt.Sprintf("nodeKind(%d)", k)
	}
}

// edgeKind classifies an edge in the value-flow graph.
type edgeKind int

const (
	ekValueFlow   edgeKind = iota // SSA value feeds into another
	ekCallArg                     // Error passed as argument to callee
	ekCallReturn                  // Error returned from callee to caller
	ekBranchTrue                  // True successor of an If
	ekBranchFalse                 // False successor of an If
	ekPhiInput                    // Incoming value to a Phi
)

// vfNode is a node in the value-flow graph.
type vfNode struct {
	id       int
	kind     nodeKind
	pos      token.Position // source position for diagnostics
	label    string         // human-readable label (function + instruction)
	ssaVal   ssa.Value      // the SSA value this node represents (may be nil for synthetic nodes)
}

// vfEdge is a directed edge in the value-flow graph.
type vfEdge struct {
	from int
	to   int
	kind edgeKind
}

// vfGraph is the complete value-flow graph for one error source.
type vfGraph struct {
	nodes         []vfNode
	edges         []vfEdge
	source        int   // node ID of the error source
	exits         []int // node IDs of exit nodes
	classifySites []int // node IDs of ClassifySkippable calls
}

// vfBuilder accumulates nodes and edges while walking the SSA value graph.
type vfBuilder struct {
	graph      vfGraph
	fset       *token.FileSet
	classifyFn *ssa.Function
	cg         *callgraph.Graph
	visited    map[ssa.Value]int // SSA value → node ID (dedup)
	originFn   *ssa.Function    // function containing the original error source
}

func newVFBuilder(fset *token.FileSet, classifyFn *ssa.Function, cg *callgraph.Graph) *vfBuilder {
	return &vfBuilder{
		fset:       fset,
		classifyFn: classifyFn,
		cg:         cg,
		visited:    make(map[ssa.Value]int),
	}
}

// addNode creates a new node and returns its ID.
func (b *vfBuilder) addNode(kind nodeKind, val ssa.Value, label string) int {
	id := len(b.graph.nodes)
	pos := token.Position{}
	if val != nil {
		pos = b.fset.Position(val.Pos())
	}
	b.graph.nodes = append(b.graph.nodes, vfNode{
		id:     id,
		kind:   kind,
		pos:    pos,
		label:  label,
		ssaVal: val,
	})
	if val != nil {
		b.visited[val] = id
	}
	return id
}

// addEdge creates a directed edge.
func (b *vfBuilder) addEdge(from, to int, kind edgeKind) {
	b.graph.edges = append(b.graph.edges, vfEdge{from: from, to: to, kind: kind})
}

// extractGraph builds the value-flow graph starting from an error source.
func (b *vfBuilder) extractGraph(errVal ssa.Value, sourceLabel string) vfGraph {
	srcID := b.addNode(nkErrorSource, errVal, sourceLabel)
	b.graph.source = srcID
	b.originFn = errVal.Parent()
	b.walkValue(errVal, srcID)
	return b.graph
}

// walkValue recursively follows an SSA value through its referrers,
// emitting nodes and edges for each step.
//
// Control flow encoding:
//   - BinOp (err != nil): creates branch, all other referrers gated through true branch
//   - ClassifySkippable: creates a sub-branch (op != nil / op == nil).
//     Classified path → exit (error swallowed).
//     Not-classified path → remaining referrers (fmt.Errorf, Return, etc.)
//   - This captures the sequential nature: error is ALWAYS tested by ClassifySkippable
//     first, then either swallowed or propagated.
func (b *vfBuilder) walkValue(val ssa.Value, fromID int) {
	refs := val.Referrers()
	if refs == nil {
		return
	}

	// Pre-scan: check for BinOp and ALL ClassifySkippable calls among referrers.
	// A ClassifySkippable call can be:
	//   - Direct static call: ClassifySkippable(err, ...)
	//   - Indirect call through function value: s.classifyFn(err, ...)
	//     resolved by VTA to ClassifySkippable
	hasBinOp := false
	var classifyCalls []*ssa.Call
	for _, instr := range *refs {
		if _, ok := instr.(*ssa.BinOp); ok {
			hasBinOp = true
		}
		if call, ok := instr.(*ssa.Call); ok {
			if b.isClassifySkippableCall(call, val) {
				classifyCalls = append(classifyCalls, call)
			}
		}
	}

	// Build a set for fast lookup of classify calls to skip in the main loop.
	classifyCallSet := make(map[*ssa.Call]bool)
	for _, c := range classifyCalls {
		classifyCallSet[c] = true
	}

	// Gate 1: BinOp creates an err-nil/err-non-nil branch.
	effectiveFromID := fromID
	if hasBinOp {
		branchID := b.addNode(nkBranch, nil, fmt.Sprintf("err check in %s", val.Parent().Name()))
		b.addEdge(fromID, branchID, ekValueFlow)

		trueID := b.addNode(nkValueFlow, nil, "err-non-nil path")
		b.addEdge(branchID, trueID, ekBranchTrue)

		falseID := b.addNode(nkReturnNil, nil, "err-nil path")
		b.addEdge(branchID, falseID, ekBranchFalse)

		effectiveFromID = trueID
	}

	// Gate 2: Chain ALL ClassifySkippable calls sequentially.
	// For each call, determine the actual control flow from the SSA:
	//   - Result used AND true-branch returns → sub-branch: classified-exit vs continue
	//   - Result used but true-branch does NOT return → classification counts but
	//     error continues regardless (no branch — both classify and remainder execute)
	//   - Result unused (standalone call) → always counts, error continues
	remainderFromID := effectiveFromID
	for _, classifyCall := range classifyCalls {
		classifyID := b.addNode(nkClassify, classifyCall,
			fmt.Sprintf("ClassifySkippable at %s", b.fset.Position(classifyCall.Pos())))
		b.addEdge(remainderFromID, classifyID, ekValueFlow)

		// Determine the true-branch behavior from the SSA.
		trueBranchReturns := classifyTrueBranchReturns(classifyCall)

		if trueBranchReturns {
			// Standard pattern: if op != nil { record; return nil }
			// The true-branch returns, making classify and remainder exclusive.
			subBranchID := b.addNode(nkBranch, nil,
				fmt.Sprintf("classify-result at %s", b.fset.Position(classifyCall.Pos())))
			b.addEdge(classifyID, subBranchID, ekValueFlow)

			exitID := b.addNode(nkExit, nil,
				fmt.Sprintf("classified-exit at %s", b.fset.Position(classifyCall.Pos())))
			b.addEdge(subBranchID, exitID, ekBranchTrue)
			b.graph.exits = append(b.graph.exits, exitID)
			b.graph.classifySites = append(b.graph.classifySites, exitID)

			continueID := b.addNode(nkValueFlow, nil,
				fmt.Sprintf("not-classified at %s", b.fset.Position(classifyCall.Pos())))
			b.addEdge(subBranchID, continueID, ekBranchFalse)

			remainderFromID = continueID
		} else {
			// Either result is unused (standalone call) or the true-branch
			// does NOT return (error leaks). In both cases, the classification
			// always counts and the error continues on the same path.
			b.graph.classifySites = append(b.graph.classifySites, classifyID)
			remainderFromID = classifyID
		}
	}

	// Process remaining referrers (connected from remainderFromID).
	for _, instr := range *refs {
		switch v := instr.(type) {
		case *ssa.Call:
			// Skip ClassifySkippable calls — already handled above.
			if classifyCallSet[v] {
				continue
			}
			b.handleCall(val, v, remainderFromID)

		case *ssa.Return:
			b.handleReturn(val, v, remainderFromID)

		case *ssa.BinOp:
			// Already handled above.

		case *ssa.Phi:
			if nodeID, seen := b.visited[v]; seen {
				b.addEdge(remainderFromID, nodeID, ekPhiInput)
			} else {
				nodeID := b.addNode(nkPhi, v, fmt.Sprintf("phi in %s", v.Parent().Name()))
				b.addEdge(remainderFromID, nodeID, ekPhiInput)
				b.walkValue(v, nodeID)
			}

		case *ssa.ChangeInterface:
			if nodeID, seen := b.visited[v]; seen {
				b.addEdge(remainderFromID, nodeID, ekValueFlow)
			} else {
				nodeID := b.addNode(nkValueFlow, v, "ChangeInterface")
				b.addEdge(remainderFromID, nodeID, ekValueFlow)
				b.walkValue(v, nodeID)
			}

		case *ssa.MakeInterface:
			if nodeID, seen := b.visited[v]; seen {
				b.addEdge(remainderFromID, nodeID, ekValueFlow)
			} else {
				nodeID := b.addNode(nkValueFlow, v, "MakeInterface")
				b.addEdge(remainderFromID, nodeID, ekValueFlow)
				b.walkValue(v, nodeID)
			}

		case *ssa.Store:
			b.handleStore(v, remainderFromID)

		case *ssa.MakeClosure:
			b.handleMakeClosure(val, v, remainderFromID)

		case *ssa.Extract:
			// Extract from a tuple (e.g., multi-return). The extracted value
			// may carry the error.
			if isErrorType(v.Type()) {
				if nodeID, seen := b.visited[v]; seen {
					b.addEdge(remainderFromID, nodeID, ekValueFlow)
				} else {
					nodeID := b.addNode(nkValueFlow, v, fmt.Sprintf("extract[%d]", v.Index))
					b.addEdge(remainderFromID, nodeID, ekValueFlow)
					b.walkValue(v, nodeID)
				}
			}

		case *ssa.Send:
			// Error sent to a channel. Trace through channel receives.
			b.handleSend(v, remainderFromID)

		case *ssa.Select:
			// Select on channels — trace received error values.
			if isErrorType(v.Type()) {
				if nodeID, seen := b.visited[v]; seen {
					b.addEdge(remainderFromID, nodeID, ekValueFlow)
				} else {
					nodeID := b.addNode(nkValueFlow, v, "select")
					b.addEdge(remainderFromID, nodeID, ekValueFlow)
					b.walkValue(v, nodeID)
				}
			}

		case *ssa.TypeAssert:
			if isErrorType(v.Type()) {
				if nodeID, seen := b.visited[v]; seen {
					b.addEdge(remainderFromID, nodeID, ekValueFlow)
				} else {
					nodeID := b.addNode(nkValueFlow, v, "type-assert")
					b.addEdge(remainderFromID, nodeID, ekValueFlow)
					b.walkValue(v, nodeID)
				}
			}

		case *ssa.FieldAddr:
			b.handleFieldAddr(v, remainderFromID)

		case *ssa.IndexAddr:
			b.handleIndexAddr(v, remainderFromID)

		default:
			// Catch-all: if the instruction produces an error-typed value,
			// trace it. This handles SSA instructions we don't have specific
			// handlers for (Lookup, Range, Next, etc.).
			if valInstr, ok := instr.(ssa.Value); ok && isErrorType(valInstr.Type()) {
				if nodeID, seen := b.visited[valInstr]; seen {
					b.addEdge(remainderFromID, nodeID, ekValueFlow)
				} else {
					nodeID := b.addNode(nkValueFlow, valInstr,
						fmt.Sprintf("value-flow(%T)", instr))
					b.addEdge(remainderFromID, nodeID, ekValueFlow)
					b.walkValue(valInstr, nodeID)
				}
			}
		}
	}
}

// handleCall processes a call instruction that uses the error value.
func (b *vfBuilder) handleCall(errVal ssa.Value, call *ssa.Call, fromID int) {
	cc := call.Common()
	callee := cc.StaticCallee()

	// ClassifySkippable (direct or indirect) is handled in walkValue pre-scan.
	if b.isClassifySkippableCall(call, errVal) {
		return
	}

	// Check if this is fmt.Errorf (wrapping pattern).
	if callee != nil && callee.Pkg != nil && callee.Pkg.Pkg != nil &&
		callee.Pkg.Pkg.Path() == "fmt" && callee.Name() == "Errorf" {
		nodeID := b.addNode(nkWrap, call, fmt.Sprintf("fmt.Errorf at %s", b.fset.Position(call.Pos())))
		b.addEdge(fromID, nodeID, ekValueFlow)
		// The wrapped error is a new value — trace it through its referrers.
		b.walkValue(call, nodeID)
		return
	}

	// Error passed as argument to a non-classify, non-wrapping callee.
	argIdx := -1
	for i, arg := range cc.Args {
		if arg == errVal {
			argIdx = i
			break
		}
	}
	if argIdx < 0 {
		return
	}

	callLabel := "call"
	if callee != nil {
		callLabel = callee.Name()
	}
	nodeID := b.addNode(nkCall, call, fmt.Sprintf("call %s at %s", callLabel, b.fset.Position(call.Pos())))
	b.addEdge(fromID, nodeID, ekCallArg)

	b.traceIntoCallee(callee, argIdx, nodeID)
}

// handleReturn processes a return instruction that carries the error value.
func (b *vfBuilder) handleReturn(errVal ssa.Value, ret *ssa.Return, fromID int) {
	fn := ret.Parent()

	errIdx := -1
	for i, result := range ret.Results {
		if result == errVal {
			errIdx = i
			break
		}
	}
	if errIdx < 0 {
		return
	}

	if _, isConst := errVal.(*ssa.Const); isConst {
		nodeID := b.addNode(nkReturnNil, nil, fmt.Sprintf("return nil in %s", fn.Name()))
		b.addEdge(fromID, nodeID, ekValueFlow)
		return
	}

	nodeID := b.addNode(nkReturn, nil, fmt.Sprintf("return err in %s", fn.Name()))
	b.addEdge(fromID, nodeID, ekValueFlow)

	b.traceReturnToCallers(fn, errIdx, nodeID)
}

// handleStore follows a stored error value through loads and varargs chains.
func (b *vfBuilder) handleStore(store *ssa.Store, fromID int) {
	addr := store.Addr
	if _, seen := b.visited[addr]; seen {
		return
	}

	// Follow direct loads from the same address.
	refs := addr.Referrers()
	if refs == nil {
		return
	}
	for _, instr := range *refs {
		if load, ok := instr.(*ssa.UnOp); ok {
			if nodeID, seen := b.visited[load]; seen {
				b.addEdge(fromID, nodeID, ekValueFlow)
			} else {
				nodeID := b.addNode(nkValueFlow, load, "load")
				b.addEdge(fromID, nodeID, ekValueFlow)
				b.walkValue(load, nodeID)
			}
		}
	}

	// For FieldAddr stores: find all other FieldAddr instructions on the same
	// base struct with the same field index, and trace through their loads.
	// This handles: h.err = sdkErr; ... if h.err != nil { ClassifySkippable(h.err) }
	if fa, ok := addr.(*ssa.FieldAddr); ok {
		b.traceFieldStore(fa, fromID)
	}

	// Varargs chain: Store to IndexAddr → base Alloc → Slice → Call (fmt.Errorf).
	b.traceVarargsChain(addr, fromID)
}

// traceFieldStore finds all loads of the same struct field from any FieldAddr
// on the same base value.
func (b *vfBuilder) traceFieldStore(fa *ssa.FieldAddr, fromID int) {
	base := fa.X
	fieldIdx := fa.Field
	baseRefs := base.Referrers()
	if baseRefs == nil {
		return
	}
	for _, instr := range *baseRefs {
		otherFA, ok := instr.(*ssa.FieldAddr)
		if !ok || otherFA == fa || otherFA.Field != fieldIdx {
			continue
		}
		// Found another FieldAddr on the same base + field. Trace its loads.
		otherRefs := otherFA.Referrers()
		if otherRefs == nil {
			continue
		}
		for _, otherInstr := range *otherRefs {
			if load, ok := otherInstr.(*ssa.UnOp); ok {
				if nodeID, seen := b.visited[load]; seen {
					b.addEdge(fromID, nodeID, ekValueFlow)
				} else {
					nodeID := b.addNode(nkValueFlow, load, fmt.Sprintf("field-load[%d]", fieldIdx))
					b.addEdge(fromID, nodeID, ekValueFlow)
					b.walkValue(load, nodeID)
				}
			}
		}
	}
}

// traceVarargsChain detects the pattern: IndexAddr on Alloc → Slice → fmt.Errorf call.
// If found, connects the error to the fmt.Errorf result as a Wrap node.
func (b *vfBuilder) traceVarargsChain(addr ssa.Value, fromID int) {
	// addr should be an IndexAddr instruction.
	idxAddr, ok := addr.(*ssa.IndexAddr)
	if !ok {
		return
	}
	// The base of the IndexAddr is the array (Alloc).
	base := idxAddr.X
	baseRefs := base.Referrers()
	if baseRefs == nil {
		return
	}
	// Look for a Slice on the base array.
	for _, instr := range *baseRefs {
		sliceInstr, ok := instr.(*ssa.Slice)
		if !ok {
			continue
		}
		// Look for a Call that uses the Slice as an argument.
		sliceRefs := sliceInstr.Referrers()
		if sliceRefs == nil {
			continue
		}
		for _, sliceRef := range *sliceRefs {
			call, ok := sliceRef.(*ssa.Call)
			if !ok {
				continue
			}
			callee := call.Common().StaticCallee()
			if callee == nil {
				continue
			}
			// Check if this is fmt.Errorf.
			if callee.Pkg != nil && callee.Pkg.Pkg != nil &&
				callee.Pkg.Pkg.Path() == "fmt" && callee.Name() == "Errorf" {
				if nodeID, seen := b.visited[call]; seen {
					b.addEdge(fromID, nodeID, ekValueFlow)
				} else {
					nodeID := b.addNode(nkWrap, call,
						fmt.Sprintf("fmt.Errorf at %s", b.fset.Position(call.Pos())))
					b.addEdge(fromID, nodeID, ekValueFlow)
					b.walkValue(call, nodeID)
				}
			}
		}
	}
}

// traceIntoCallee follows an error argument into a callee's body via its parameter.
func (b *vfBuilder) traceIntoCallee(callee *ssa.Function, argIdx int, callNodeID int) {
	if callee == nil || callee.Blocks == nil {
		return
	}
	if argIdx >= len(callee.Params) {
		return
	}
	param := callee.Params[argIdx]
	if !isErrorType(param.Type()) {
		return
	}

	if nodeID, seen := b.visited[param]; seen {
		b.addEdge(callNodeID, nodeID, ekCallArg)
		return
	}
	nodeID := b.addNode(nkValueFlow, param, fmt.Sprintf("param %s of %s", param.Name(), callee.Name()))
	b.addEdge(callNodeID, nodeID, ekCallArg)
	b.walkValue(param, nodeID)
}

// traceReturnToCallers uses the VTA call graph to find callers of fn and
// traces the error at each call site.
//
// Only creates exit nodes for:
// - The origin function (where the AWS SDK error was produced)
// - Functions with no callers that are the origin or its enclosing function
//
// Functions with no callers that are NOT the origin (dead code paths, VTA
// limitations) don't produce exits — the error chain terminates without
// an exit, making the path invisible to Z3.
func (b *vfBuilder) traceReturnToCallers(fn *ssa.Function, errIdx int, returnNodeID int) {
	node := b.cg.Nodes[fn]
	noCallers := node == nil || len(node.In) == 0

	if noCallers {
		// For closures with no VTA callers: trace through the parent's
		// MakeClosure → the call that receives the closure → that call's
		// error return. This handles Paginate(func() (bool, error) { ... })
		// where VTA can't resolve that Paginate calls the closure.
		parent := fn.Parent()
		if parent != nil && parent.Blocks != nil {
			traced := false
			for _, block := range parent.Blocks {
				for _, instr := range block.Instrs {
					mc, ok := instr.(*ssa.MakeClosure)
					if !ok {
						continue
					}
					closureFn, ok := mc.Fn.(*ssa.Function)
					if !ok || closureFn != fn {
						continue
					}
					// Found the MakeClosure for this closure. Find the call
					// that receives it and trace the error return.
					if refs := mc.Referrers(); refs != nil {
						for _, ref := range *refs {
							call, ok := ref.(*ssa.Call)
							if !ok {
								continue
							}
							callErrVal := extractErrorFromCall(call)
							if callErrVal == nil {
								continue
							}
							if nodeID, seen := b.visited[callErrVal]; seen {
								b.addEdge(returnNodeID, nodeID, ekCallReturn)
							} else {
								nodeID := b.addNode(nkCallResult, callErrVal,
									fmt.Sprintf("closure-caller result in %s at %s",
										call.Parent().Name(), b.fset.Position(call.Pos())))
								b.addEdge(returnNodeID, nodeID, ekCallReturn)
								b.walkValue(callErrVal, nodeID)
							}
							traced = true
						}
					}
				}
			}
			if traced {
				return
			}
		}

		// Fallback: create exit only for origin function or its parent.
		isOrigin := fn == b.originFn
		isOriginParent := b.originFn != nil && b.originFn.Parent() == fn
		if isOrigin || isOriginParent {
			exitID := b.addNode(nkExit, nil, fmt.Sprintf("exit from %s", fn.Name()))
			b.addEdge(returnNodeID, exitID, ekCallReturn)
			b.graph.exits = append(b.graph.exits, exitID)
		}
		return
	}

	for _, edge := range node.In {
		callInstr := edge.Site
		if callInstr == nil {
			continue
		}
		call, ok := callInstr.(*ssa.Call)
		if !ok {
			continue
		}

		var errAtCaller ssa.Value

		if refs := call.Referrers(); refs != nil {
			for _, ref := range *refs {
				if ext, ok := ref.(*ssa.Extract); ok && ext.Index == errIdx {
					errAtCaller = ext
					break
				}
			}
		}
		if errAtCaller == nil && errIdx == 0 && isErrorType(call.Type()) {
			errAtCaller = call
		}

		if errAtCaller == nil {
			continue
		}

		if nodeID, seen := b.visited[errAtCaller]; seen {
			b.addEdge(returnNodeID, nodeID, ekCallReturn)
			continue
		}

		nodeID := b.addNode(nkCallResult, errAtCaller,
			fmt.Sprintf("call result in %s at %s", call.Parent().Name(), b.fset.Position(call.Pos())))
		b.addEdge(returnNodeID, nodeID, ekCallReturn)
		b.walkValue(errAtCaller, nodeID)
	}
}

// handleMakeClosure traces an error value captured by a closure.
func (b *vfBuilder) handleMakeClosure(errVal ssa.Value, mc *ssa.MakeClosure, fromID int) {
	closureFn, ok := mc.Fn.(*ssa.Function)
	if !ok {
		return
	}

	for i, binding := range mc.Bindings {
		if binding != errVal {
			continue
		}
		if i >= len(closureFn.FreeVars) {
			continue
		}
		freeVar := closureFn.FreeVars[i]
		if !isErrorType(freeVar.Type()) {
			continue
		}

		if nodeID, seen := b.visited[freeVar]; seen {
			b.addEdge(fromID, nodeID, ekValueFlow)
			continue
		}
		nodeID := b.addNode(nkValueFlow, freeVar,
			fmt.Sprintf("freevar %s in closure %s", freeVar.Name(), closureFn.Name()))
		b.addEdge(fromID, nodeID, ekValueFlow)
		b.walkValue(freeVar, nodeID)
	}

	if refs := mc.Referrers(); refs != nil {
		for _, ref := range *refs {
			call, ok := ref.(*ssa.Call)
			if !ok {
				continue
			}
			callErrVal := extractErrorFromCall(call)
			if callErrVal == nil {
				continue
			}
			if nodeID, seen := b.visited[callErrVal]; seen {
				b.addEdge(fromID, nodeID, ekCallReturn)
				continue
			}
			nodeID := b.addNode(nkCallResult, callErrVal,
				fmt.Sprintf("closure-caller result in %s at %s", call.Parent().Name(), b.fset.Position(call.Pos())))
			b.addEdge(fromID, nodeID, ekCallReturn)
			b.walkValue(callErrVal, nodeID)
		}
	}
}

// isClassifySkippableCall checks if a call instruction invokes ClassifySkippable
// (directly or through a function value resolved by VTA) with val as the first arg.
func (b *vfBuilder) isClassifySkippableCall(call *ssa.Call, val ssa.Value) bool {
	cc := call.Common()

	// Check the first argument is our error value.
	if len(cc.Args) == 0 || cc.Args[0] != val {
		return false
	}

	// Direct static call.
	if callee := cc.StaticCallee(); callee == b.classifyFn {
		return true
	}

	// Indirect call — use VTA to resolve callees.
	if node := b.cg.Nodes[call.Parent()]; node != nil {
		for _, edge := range node.Out {
			if edge.Site == call && edge.Callee != nil {
				if edge.Callee.Func == b.classifyFn {
					return true
				}
			}
		}
	}

	return false
}

// handleSend traces an error sent to a channel. Finds all Recv (UnOp) on the
// same channel and traces the received value.
func (b *vfBuilder) handleSend(send *ssa.Send, fromID int) {
	ch := send.Chan
	chRefs := ch.Referrers()
	if chRefs == nil {
		return
	}
	for _, instr := range *chRefs {
		// A channel receive in SSA is a UnOp with Op == token.ARROW (<-ch).
		if recv, ok := instr.(*ssa.UnOp); ok && recv.Op == token.ARROW {
			// The received value may be the error. For typed channels (chan error),
			// the recv itself is the error value.
			if isErrorType(recv.Type()) {
				if nodeID, seen := b.visited[recv]; seen {
					b.addEdge(fromID, nodeID, ekValueFlow)
				} else {
					nodeID := b.addNode(nkValueFlow, recv, "channel-recv")
					b.addEdge(fromID, nodeID, ekValueFlow)
					b.walkValue(recv, nodeID)
				}
			}
			// For untyped channels or tuples (select), the error may be extracted.
			if tup, ok := recv.Type().(*types.Tuple); ok {
				for i := 0; i < tup.Len(); i++ {
					if isErrorType(tup.At(i).Type()) {
						if recvRefs := recv.Referrers(); recvRefs != nil {
							for _, rr := range *recvRefs {
								if ext, ok := rr.(*ssa.Extract); ok && ext.Index == i {
									if nodeID, seen := b.visited[ext]; seen {
										b.addEdge(fromID, nodeID, ekValueFlow)
									} else {
										nodeID := b.addNode(nkValueFlow, ext, "channel-recv-extract")
										b.addEdge(fromID, nodeID, ekValueFlow)
										b.walkValue(ext, nodeID)
									}
								}
							}
						}
					}
				}
			}
		}
	}
}

// handleFieldAddr traces an error value through a struct field pointer.
// When an error is stored to a FieldAddr, any load from the same FieldAddr
// (on the same base) carries the error.
func (b *vfBuilder) handleFieldAddr(fa *ssa.FieldAddr, fromID int) {
	faRefs := fa.Referrers()
	if faRefs == nil {
		return
	}
	for _, instr := range *faRefs {
		if load, ok := instr.(*ssa.UnOp); ok {
			if nodeID, seen := b.visited[load]; seen {
				b.addEdge(fromID, nodeID, ekValueFlow)
			} else {
				nodeID := b.addNode(nkValueFlow, load, fmt.Sprintf("field-load[%d]", fa.Field))
				b.addEdge(fromID, nodeID, ekValueFlow)
				b.walkValue(load, nodeID)
			}
		}
	}
}

// handleIndexAddr traces an error value through a slice/array index pointer.
func (b *vfBuilder) handleIndexAddr(ia *ssa.IndexAddr, fromID int) {
	iaRefs := ia.Referrers()
	if iaRefs == nil {
		return
	}
	for _, instr := range *iaRefs {
		if load, ok := instr.(*ssa.UnOp); ok {
			if nodeID, seen := b.visited[load]; seen {
				b.addEdge(fromID, nodeID, ekValueFlow)
			} else {
				nodeID := b.addNode(nkValueFlow, load, "index-load")
				b.addEdge(fromID, nodeID, ekValueFlow)
				b.walkValue(load, nodeID)
			}
		}
	}
}

// classifyTrueBranchReturns checks if the ClassifySkippable call's result
// leads to a branch whose true-path exclusively returns (i.e., the
// function returns after classification, swallowing the error, and the
// true-path does NOT merge back to the false-path).
//
// The check: find the If that branches on the classify result. The If has
// two successors: Succs[0] (true) and Succs[1] (false). Check if the true
// branch reaches a Return WITHOUT passing through any block that is also
// reachable from the false branch. This distinguishes:
//   - if op != nil { return nil }     → true-branch returns exclusively
//   - if op != nil { record(op) }     → true-branch falls through to shared code
func classifyTrueBranchReturns(classifyCall *ssa.Call) bool {
	callRefs := classifyCall.Referrers()
	if callRefs == nil {
		return false
	}

	// Find all If instructions that depend on the classify result.
	var ifs []*ssa.If
	var findIfs func(val ssa.Value, depth int)
	findIfs = func(val ssa.Value, depth int) {
		if depth > 3 {
			return
		}
		refs := val.Referrers()
		if refs == nil {
			return
		}
		for _, ref := range *refs {
			switch v := ref.(type) {
			case *ssa.If:
				ifs = append(ifs, v)
			case *ssa.BinOp:
				findIfs(v, depth+1)
			}
		}
	}
	findIfs(classifyCall, 0)

	if len(ifs) == 0 {
		return false
	}

	for _, ifInstr := range ifs {
		block := ifInstr.Block()
		if len(block.Succs) < 2 {
			continue
		}
		trueBranch := block.Succs[0]
		falseBranch := block.Succs[1]

		// Collect all blocks reachable from the false branch.
		falseReachable := collectReachableBlocks(falseBranch, make(map[*ssa.BasicBlock]bool))

		// Check if the true branch reaches a Return WITHOUT going through
		// any block that's also reachable from the false branch.
		if trueBranchReturnsExclusively(trueBranch, falseReachable, make(map[*ssa.BasicBlock]bool)) {
			return true
		}
	}
	return false
}

// collectReachableBlocks returns all blocks reachable from start.
func collectReachableBlocks(start *ssa.BasicBlock, visited map[*ssa.BasicBlock]bool) map[*ssa.BasicBlock]bool {
	if visited[start] {
		return visited
	}
	visited[start] = true
	for _, succ := range start.Succs {
		collectReachableBlocks(succ, visited)
	}
	return visited
}

// trueBranchReturnsExclusively checks if the true branch reaches a Return
// instruction without going through any block shared with the false branch.
func trueBranchReturnsExclusively(block *ssa.BasicBlock, falseReachable map[*ssa.BasicBlock]bool, visited map[*ssa.BasicBlock]bool) bool {
	if visited[block] {
		return false
	}
	visited[block] = true

	// If this block is also reachable from the false branch, it's shared
	// code (post-dominator). The true branch merged back — not exclusive.
	if falseReachable[block] {
		return false
	}

	// Check for Return in this block.
	for _, instr := range block.Instrs {
		if _, ok := instr.(*ssa.Return); ok {
			return true
		}
	}

	// Follow successors.
	for _, succ := range block.Succs {
		if trueBranchReturnsExclusively(succ, falseReachable, visited) {
			return true
		}
	}
	return false
}

// emitSMTLIB2 generates an SMT-LIB2 program that checks whether there exists
// an execution path from the error source to an exit where the number of
// ClassifySkippable calls is NOT exactly 1. If unsatisfiable, the property holds.
func emitSMTLIB2(g *vfGraph) string {
	var sb strings.Builder
	sb.WriteString("; Z3 ClassifySkippable exactly-once verification\n")
	sb.WriteString("(set-logic QF_LIA)\n\n")

	for _, n := range g.nodes {
		fmt.Fprintf(&sb, "(declare-const reach_%d Bool)  ; %s: %s\n", n.id, n.kind, n.label)
	}
	sb.WriteString("\n")
	classifySet := make(map[int]bool)
	for _, cid := range g.classifySites {
		classifySet[cid] = true
		fmt.Fprintf(&sb, "(declare-const classify_%d Int)  ; classify site\n", cid)
	}
	sb.WriteString("\n")

	fmt.Fprintf(&sb, "; Error source is always reached\n")
	fmt.Fprintf(&sb, "(assert reach_%d)\n\n", g.source)

	succs := make(map[int][]int)
	preds := make(map[int][]int)
	branchSuccs := make(map[int][2]int)
	for _, e := range g.edges {
		succs[e.from] = append(succs[e.from], e.to)
		preds[e.to] = append(preds[e.to], e.from)
		if e.kind == ekBranchTrue {
			pair := branchSuccs[e.from]
			pair[0] = e.to
			branchSuccs[e.from] = pair
		}
		if e.kind == ekBranchFalse {
			pair := branchSuccs[e.from]
			pair[1] = e.to
			branchSuccs[e.from] = pair
		}
	}

	// Identify Return nodes — they return to exactly one caller (exclusive choice).
	returnNodes := make(map[int]bool)
	for _, n := range g.nodes {
		if n.kind == nkReturn {
			returnNodes[n.id] = true
		}
	}

	sb.WriteString("; Forward reachability\n")
	for nodeID, ss := range succs {
		if len(ss) == 0 {
			continue
		}
		_, isBranch := branchSuccs[nodeID]
		isReturn := returnNodes[nodeID]
		if isBranch || isReturn {
			// Branch nodes: exclusivity via xor constraint below.
			// Return nodes: return to exactly one caller (exclusive choice).
			// Both use "at least one successor" forward reachability.
			if len(ss) == 1 {
				fmt.Fprintf(&sb, "(assert (=> reach_%d reach_%d))\n", nodeID, ss[0])
			} else {
				parts := make([]string, len(ss))
				for i, s := range ss {
					parts[i] = fmt.Sprintf("reach_%d", s)
				}
				fmt.Fprintf(&sb, "(assert (=> reach_%d (or %s)))\n", nodeID, strings.Join(parts, " "))
			}
		} else {
			// Non-branch, non-return nodes: ALL successors are reached.
			for _, s := range ss {
				fmt.Fprintf(&sb, "(assert (=> reach_%d reach_%d))\n", nodeID, s)
			}
		}
	}
	sb.WriteString("\n")

	sb.WriteString("; Backward reachability\n")
	for nodeID, pp := range preds {
		if nodeID == g.source {
			continue
		}
		if len(pp) == 0 {
			continue
		}
		if len(pp) == 1 {
			fmt.Fprintf(&sb, "(assert (=> reach_%d reach_%d))\n", nodeID, pp[0])
		} else {
			parts := make([]string, len(pp))
			for i, p := range pp {
				parts[i] = fmt.Sprintf("reach_%d", p)
			}
			fmt.Fprintf(&sb, "(assert (=> reach_%d (or %s)))\n", nodeID, strings.Join(parts, " "))
		}
	}
	sb.WriteString("\n")

	sb.WriteString("; Branch exclusivity\n")
	for branchID, pair := range branchSuccs {
		fmt.Fprintf(&sb, "(assert (=> reach_%d (xor reach_%d reach_%d)))\n", branchID, pair[0], pair[1])
	}
	sb.WriteString("\n")

	// Return exclusivity: a function returns to exactly one caller per
	// invocation. But the same function can be called multiple times from
	// the same parent — those call sites all execute and are NOT exclusive.
	// Only apply exclusivity between callers in DIFFERENT parent functions.
	sb.WriteString("; Return exclusivity (one caller per invocation, across different callers)\n")
	for nodeID := range returnNodes {
		ss := succs[nodeID]
		if len(ss) <= 1 {
			continue
		}
		// Group successors by their parent function.
		// CallResult nodes in the same parent function can all execute;
		// CallResult nodes in different parent functions are exclusive.
		parentOf := make(map[int]string)
		for _, s := range ss {
			if s < len(g.nodes) && g.nodes[s].ssaVal != nil {
				if fn := g.nodes[s].ssaVal.Parent(); fn != nil {
					parentOf[s] = fn.String()
				}
			}
		}
		for i := 0; i < len(ss); i++ {
			for j := i + 1; j < len(ss); j++ {
				pi, pj := parentOf[ss[i]], parentOf[ss[j]]
				if pi != "" && pj != "" && pi != pj {
					fmt.Fprintf(&sb, "(assert (not (and reach_%d reach_%d)))\n", ss[i], ss[j])
				}
			}
		}
	}
	sb.WriteString("\n")

	sb.WriteString("; Classify counts (only classify sites — non-sites are implicitly 0)\n")
	for _, cid := range g.classifySites {
		fmt.Fprintf(&sb, "(assert (= classify_%d (ite reach_%d 1 0)))\n", cid, cid)
	}
	sb.WriteString("\n")

	sb.WriteString("; Total classify count\n")
	if len(g.classifySites) == 0 {
		sb.WriteString("(define-fun total_classify () Int 0)\n")
	} else if len(g.classifySites) == 1 {
		fmt.Fprintf(&sb, "(define-fun total_classify () Int classify_%d)\n", g.classifySites[0])
	} else {
		parts := make([]string, len(g.classifySites))
		for i, cid := range g.classifySites {
			parts[i] = fmt.Sprintf("classify_%d", cid)
		}
		fmt.Fprintf(&sb, "(define-fun total_classify () Int (+ %s))\n", strings.Join(parts, " "))
	}
	sb.WriteString("\n")

	sb.WriteString("; At least one exit reached\n")
	if len(g.exits) > 0 {
		parts := make([]string, len(g.exits))
		for i, eid := range g.exits {
			parts[i] = fmt.Sprintf("reach_%d", eid)
		}
		fmt.Fprintf(&sb, "(assert (or %s))\n", strings.Join(parts, " "))
	}
	sb.WriteString("\n")

	sb.WriteString("; Negate: exists a path where count != 1\n")
	sb.WriteString("(assert (not (= total_classify 1)))\n\n")

	sb.WriteString("(check-sat)\n")
	sb.WriteString("(get-model)\n")

	return sb.String()
}

// z3Result holds the output of a Z3 check.
type z3Result struct {
	sat   bool              // true if sat (violation found), false if unsat (property holds)
	model map[string]string // variable name → value (only populated on sat)
}

// runZ3 writes the SMT-LIB2 program to a temp file, runs z3, and parses the result.
func runZ3(t *testing.T, smt2 string) z3Result {
	t.Helper()

	tmpFile, err := os.CreateTemp("", "classify-once-*.smt2")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	if _, err := tmpFile.WriteString(smt2); err != nil {
		_ = tmpFile.Close()
		t.Fatalf("write smt2: %v", err)
	}
	_ = tmpFile.Close()

	cmd := exec.Command("z3", tmpFile.Name())
	out, err := cmd.Output()
	if err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			t.Fatalf("run z3: %v", err)
		}
	}

	return parseZ3Output(string(out))
}

// parseZ3Output parses Z3's stdout into a z3Result.
// Z3 outputs multi-line model entries like:
//
//	(define-fun reach_0 () Bool
//	  true)
//
// We collect name→value pairs by tracking define-fun lines and the next
// non-empty line.
func parseZ3Output(output string) z3Result {
	result := z3Result{model: make(map[string]string)}

	lines := strings.Split(output, "\n")
	var pendingName string
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "sat" {
			result.sat = true
			continue
		}
		// Start of a define-fun: may be single-line or multi-line.
		if strings.HasPrefix(line, "(define-fun ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				pendingName = parts[1]
			}
			// Check if value is on the same line: (define-fun x () Bool true)
			if len(parts) >= 5 {
				val := strings.TrimSuffix(parts[len(parts)-1], ")")
				result.model[pendingName] = val
				pendingName = ""
			}
			continue
		}
		// Continuation of a multi-line define-fun: the value line.
		if pendingName != "" && line != "" && line != "(" && line != ")" {
			val := strings.TrimSuffix(strings.TrimSpace(line), ")")
			result.model[pendingName] = val
			pendingName = ""
		}
	}

	return result
}

// diagnoseSat produces a human-readable diagnostic from a sat result.
// The diagnostic explains WHAT is wrong and HOW to fix it.
func diagnoseSat(g *vfGraph, result z3Result) string {
	var sb strings.Builder

	// Collect reached nodes and count classify sites on the path.
	var reachedNodes []vfNode
	classifyCount := 0
	classifySiteSet := make(map[int]bool)
	for _, cid := range g.classifySites {
		classifySiteSet[cid] = true
	}
	for _, n := range g.nodes {
		key := fmt.Sprintf("reach_%d", n.id)
		if result.model[key] == "true" {
			reachedNodes = append(reachedNodes, n)
			if classifySiteSet[n.id] {
				classifyCount++
			}
		}
	}

	if classifyCount == 0 {
		sb.WriteString("ERROR: ClassifySkippable count = 0 on a reachable path.\n")
		sb.WriteString("The AWS SDK error reaches an exit without being classified.\n")
		sb.WriteString("\n")
		sb.WriteString("FIX: Add ClassifySkippable(err, service, operation, region) on this path,\n")
		sb.WriteString("     or ensure the error propagates to a caller that classifies it.\n")
	} else if classifyCount > 1 {
		fmt.Fprintf(&sb, "ERROR: ClassifySkippable count = %d on a reachable path (expected exactly 1).\n", classifyCount)
		sb.WriteString("The error is classified multiple times, producing duplicate SkipReport entries.\n")
		sb.WriteString("\n")
		sb.WriteString("FIX: Ensure only ONE ClassifySkippable call is reachable per error.\n")
		sb.WriteString("     Common causes:\n")
		sb.WriteString("     - ClassifySkippable called but the function doesn't return afterward\n")
		sb.WriteString("       (error leaks to a caller that classifies again)\n")
		sb.WriteString("     - Multiple ClassifySkippable calls on the same error value\n")
	} else {
		// count == 1 but Z3 said sat — shouldn't happen with not(= total 1).
		fmt.Fprintf(&sb, "ERROR: unexpected Z3 sat with classify count = %d\n", classifyCount)
	}

	// Show the counterexample path.
	sb.WriteString("\nCounterexample path (nodes reached by Z3):\n")
	for _, n := range reachedNodes {
		posStr := ""
		if n.pos.IsValid() {
			posStr = n.pos.String()
		}
		marker := "  "
		if classifySiteSet[n.id] {
			marker = ">>"
		}
		fmt.Fprintf(&sb, "  %s [%s] %s", marker, n.kind, n.label)
		if posStr != "" {
			fmt.Fprintf(&sb, "\n       at %s", posStr)
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

// z3ErrSource holds an AWS SDK call site and the function it lives in.
type z3ErrSource struct {
	call  *ssa.Call
	label string
	fn    *ssa.Function
}

// z3Analysis holds the shared SSA/VTA state for the Z3 test.
type z3Analysis struct {
	prog       *ssa.Program
	classifyFn *ssa.Function
	cg         *callgraph.Graph
	sources    []z3ErrSource
}

// loadZ3Analysis builds SSA, VTA call graph, and collects all AWS SDK error sources.
func loadZ3Analysis(t *testing.T) *z3Analysis {
	t.Helper()

	if _, err := exec.LookPath("z3"); err != nil {
		t.Skip("z3 binary not found in PATH; install with: brew install z3")
	}

	cfg := &packages.Config{
		Mode:  packages.LoadAllSyntax,
		Dir:   ".",
		Tests: true,
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

	// With Tests: true, packages.Load returns multiple packages.
	// Find the test-augmented package — it has the most members because
	// it includes both the main package AND internal _test.go files
	// (e.g. z3_stress_enumerator_test.go with stressBug_ functions).
	var enumPkg *ssa.Package
	for _, pkg := range ssaPkgs {
		if pkg == nil || findSSAFunc(pkg, "ClassifySkippable") == nil {
			continue
		}
		if enumPkg == nil || len(pkg.Members) > len(enumPkg.Members) {
			enumPkg = pkg
		}
	}
	if enumPkg == nil {
		t.Fatal("ClassifySkippable not found in any SSA package")
	}

	classifyFn := findSSAFunc(enumPkg, "ClassifySkippable")

	allFuncs := ssautil.AllFunctions(prog)
	chaGraph := cha.CallGraph(prog)
	cg := vta.CallGraph(allFuncs, chaGraph)

	ourFuncs := collectPackageFuncs(prog, enumPkg)

	var sources []z3ErrSource
	var findSources func(fn *ssa.Function)
	findSources = func(fn *ssa.Function) {
		if fn.Blocks == nil {
			return
		}
		for _, block := range fn.Blocks {
			for _, instr := range block.Instrs {
				call, ok := instr.(*ssa.Call)
				if !ok || !isAWSSDKCall(call) {
					continue
				}
				if extractErrorFromCall(call) != nil {
					sources = append(sources, z3ErrSource{
						call:  call,
						label: describeSSACall(call),
						fn:    fn,
					})
				}
			}
		}
		for _, anon := range fn.AnonFuncs {
			findSources(anon)
		}
	}

	for _, fn := range ourFuncs {
		findSources(fn)
	}

	if len(sources) == 0 {
		t.Fatal("no AWS SDK call sites found — analysis may be broken")
	}

	return &z3Analysis{prog: prog, classifyFn: classifyFn, cg: cg, sources: sources}
}

// verifySource checks a single error source and returns a non-empty violation
// string if the exactly-once property is violated, or "" if it holds.
func (a *z3Analysis) verifySource(t *testing.T, src z3ErrSource) string {
	t.Helper()

	errVal := extractErrorFromCall(src.call)
	if errVal == nil {
		return ""
	}

	builder := newVFBuilder(a.prog.Fset, a.classifyFn, a.cg)
	graph := builder.extractGraph(errVal, src.label)
	pos := a.prog.Fset.Position(src.call.Pos())

	fnReturnsError := false
	if sig := src.fn.Signature; sig != nil {
		results := sig.Results()
		for i := 0; i < results.Len(); i++ {
			if isErrorType(results.At(i).Type()) {
				fnReturnsError = true
				break
			}
		}
	}

	if len(graph.exits) == 0 {
		if os.Getenv("Z3_DEBUG") != "" {
			t.Logf("Graph for %s at %s: %d nodes, %d edges, %d exits, %d classify sites",
				src.label, pos, len(graph.nodes), len(graph.edges), len(graph.exits), len(graph.classifySites))
			for _, n := range graph.nodes {
				t.Logf("  node[%d] %s: %s (pos: %s)", n.id, n.kind, n.label, n.pos)
			}
			for _, e := range graph.edges {
				t.Logf("  edge %d → %d (%d)", e.from, e.to, e.kind)
			}
		}
		if len(graph.classifySites) > 0 {
			// The graph has classify sites but no exits. This happens when:
			// - The classify pattern is "classify, record, continue" (not return)
			// - The error is absorbed by the caller after classification
			// Add an implicit exit after each terminal classify site (one with
			// no successors leading to another classify or exit).
			for _, cid := range graph.classifySites {
				exitID := len(graph.nodes)
				graph.nodes = append(graph.nodes, vfNode{
					id: exitID, kind: nkExit, label: "implicit-exit (error absorbed after classify)",
				})
				graph.edges = append(graph.edges, vfEdge{
					from: cid, to: exitID, kind: ekValueFlow,
				})
				graph.exits = append(graph.exits, exitID)
			}
		} else {
			return fmt.Sprintf("%s at %s:\n"+
				"  ERROR: AWS SDK error is never classified by ClassifySkippable.\n"+
				"  The error from %s has no path to ClassifySkippable on any execution path.\n"+
				"\n"+
				"  FIX: Add error handling that calls ClassifySkippable(err, service, operation, region).\n"+
				"  If the error is intentionally non-fatal, still classify it so it appears in the SkipReport.\n"+
				"  Standard pattern:\n"+
				"    if op := ClassifySkippable(err, \"service\", \"Operation\", region); op != nil {\n"+
				"        skipReport.RecordBatch([]SkippedOp{*op})\n"+
				"        return nil\n"+
				"    }\n"+
				"    return fmt.Errorf(\"operation failed: %%w\", err)\n",
				src.fn.Name(), pos, src.label)
		}
	}

	if fnReturnsError {
		succCount := make(map[int]int)
		for _, e := range graph.edges {
			succCount[e.from]++
		}
		for _, n := range graph.nodes {
			if strings.HasPrefix(n.label, "not-classified") && succCount[n.id] == 0 {
				return fmt.Sprintf("%s at %s:\n"+
					"  ERROR: Error silently dropped when ClassifySkippable returns nil.\n"+
					"  When ClassifySkippable(err, ...) returns nil (error is NOT a skippable AWS error),\n"+
					"  the error must be propagated to the caller via return, not silently swallowed.\n"+
					"\n"+
					"  FIX: Add 'return fmt.Errorf(\"operation: %%w\", err)' after the ClassifySkippable check:\n"+
					"    if op := ClassifySkippable(err, ...); op != nil {\n"+
					"        record(op)\n"+
					"        return nil   // ← classified, swallowed\n"+
					"    }\n"+
					"    return fmt.Errorf(\"...: %%w\", err)  // ← not classified, propagate\n",
					src.fn.Name(), pos)
			}
		}
	}

	smt2 := emitSMTLIB2(&graph)

	if os.Getenv("Z3_DEBUG") != "" {
		t.Logf("SMT-LIB2 for %s at %s:\n%s", src.label, pos, smt2)
	}

	result := runZ3(t, smt2)
	if result.sat {
		return fmt.Sprintf("%s at %s:\n%s",
			src.fn.Name(), pos, diagnoseSat(&graph, result))
	}

	return ""
}

// isBugPattern returns true if the source is a deliberate bug pattern
// (stressBug_ prefix). Used to exclude them from correct-sources and
// include them in the bug-detection test.
func isBugPattern(src z3ErrSource) bool {
	return isStressBugFunc(src.fn)
}

// testClassifySkippableExactlyOnce_Z3 is the Z3 implementation of the
// exactly-once property check. For each AWS SDK error source, it builds a
// value-flow graph, emits SMT-LIB2 constraints, and asks Z3 whether any
// execution path exists where ClassifySkippable count != 1.
func testClassifySkippableExactlyOnce_Z3(t *testing.T) {
	t.Helper()
	a := loadZ3Analysis(t)

	var correctSources []z3ErrSource
	for _, src := range a.sources {
		if !isBugPattern(src) {
			correctSources = append(correctSources, src)
		}
	}

	t.Logf("verifying %d correct sources (%d total, %d excluded)",
		len(correctSources), len(a.sources), len(a.sources)-len(correctSources))

	for _, src := range correctSources {
		t.Run(fmt.Sprintf("%s_%s", src.fn.Name(), src.label), func(t *testing.T) {
			if violation := a.verifySource(t, src); violation != "" {
				t.Error(violation)
			}
		})
	}
}

// TestClassifySkippableExactlyOnce_BugPatterns verifies that the Z3 analysis
// correctly detects deliberate bug patterns (stressBug_ functions in
// z3_stress_enumerator_test.go). Each pattern violates the exactly-once
// property in a specific way: silent drops (count=0), double classification
// (count=2), classify-then-leak, wrong error classified, etc.
// Requires z3 — skips if not installed.
func TestClassifySkippableExactlyOnce_BugPatterns(t *testing.T) {
	a := loadZ3Analysis(t)

	var bugSources []z3ErrSource
	for _, src := range a.sources {
		if isBugPattern(src) {
			bugSources = append(bugSources, src)
		}
	}

	if len(bugSources) == 0 {
		t.Fatal("no bug patterns found — stress test file may be missing")
	}

	t.Logf("verifying %d bug patterns are detected", len(bugSources))

	// Known limitation: stressBug_oneCallerDrops calls a closure twice with
	// different error handling at each call site. SSA has one function body
	// with one SDK call, so per-error-source analysis can't distinguish the
	// two invocations. This requires per-call-site analysis.
	knownLimitations := map[string]bool{
		"stressBug_oneCallerDrops": true,
	}

	for _, src := range bugSources {
		t.Run(fmt.Sprintf("%s_%s", src.fn.Name(), src.label), func(t *testing.T) {
			violation := a.verifySource(t, src)
			parentName := ""
			if p := src.fn.Parent(); p != nil {
				parentName = p.Name()
			}
			isKnownLimitation := knownLimitations[src.fn.Name()] || knownLimitations[parentName]

			if violation == "" && !isKnownLimitation {
				t.Errorf("expected violation for bug pattern %s but none was found — "+
					"the Z3 test failed to detect the deliberately broken error handling",
					src.fn.Name())
			} else if violation == "" && isKnownLimitation {
				t.Logf("known limitation: %s (per-call-site analysis needed)", src.fn.Name())
			} else {
				t.Logf("correctly detected: %s", strings.Split(violation, "\n")[0])
			}
		})
	}
}
