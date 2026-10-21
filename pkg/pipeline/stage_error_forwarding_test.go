package pipeline

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// This file pins the shape ENG-9014 regressed: losing `out`'s closeOnce does
// NOT mean the stage error was lost. publishStageErr's guardrail warning must
// fire ONLY when the winning close recorded no error at all.
//
// The shape, which is what cmd/generator.go's `pipeline.Pipe(p1, module.Run, p2)`
// produces whenever a module's Run hands p2 to an inner Pipe:
//
//	stage := func(_ int, out *P[string]) error {
//	    Pipe(From("a"), failing, out) // inner Pipe OWNS out; FAILS, records E
//	    return out.Wait()             // ← returns that same E
//	}
//
// module.Run is itself a stage of an outer Pipe, so publishStageErr runs with
// stageErr == E and loses out.closeOnce. The prior close recorded E, the
// caller's Wait() already returns E, and there is nothing to warn about.
//
// Both assertions live in the same test on purpose. "No warning was emitted"
// alone could pass vacuously (nothing ran, the pipeline deadlocked, the stage
// never failed); pairing it with "the caller actually received E" is what makes
// it a real assertion, and it is the half that falsifies the old warning's
// claim that such an error "can never reach the caller".
var (
	// errInnerPipeFailure is recorded on the caller-owned `out` by the INNER
	// Pipe, which wins out.closeOnce.
	errInnerPipeFailure = errors.New("inner pipe stage failure")

	// errUnrelatedStageFailure is a stage error that is NOT the error the
	// prior close recorded — the deliberately accepted residual gap below.
	errUnrelatedStageFailure = errors.New("unrelated stage failure")
)

// sendThenFail emits one item and then fails, so the inner Pipe both moves
// real data through `out` and records an error on it. Emitting first keeps the
// tests honest: a shape that delivered the error by breaking the data flow
// would fail the item assertion.
func sendThenFail(s string, out *P[string]) error {
	out.Send("item-" + s)
	return errInnerPipeFailure
}

// pipeOpts selects the sequential path (nil) or the parallel path. Pipe treats
// a nil *PipeOpts as absent, so this covers both without branching at the call
// site.
func pipeOpts(concurrency int) *PipeOpts {
	if concurrency <= 1 {
		return nil
	}
	return &PipeOpts{Concurrency: concurrency}
}

// innerFailureStage builds the regressed stage: hand the caller-owned `out` to
// an inner Pipe that fails, then forward the inner error with `forward`.
//
// stageDone is closed by the stage's outermost defer, i.e. as the stage
// returns. The caller's Wait() is released by the INNER Pipe's close, strictly
// before the stage has returned, so Wait() returning tells us nothing about
// whether the outer publishStageErr has run yet. Waiting on stageDone narrows
// the "did the guardrail fire?" window down to the few instructions between
// the stage returning and publishStageErr executing; the grace period in
// requireNone covers that remainder.
func innerFailureStage(concurrency int, forward func(*P[string]) error, stageDone chan struct{}) func(int, *P[string]) error {
	return func(_ int, out *P[string]) error {
		defer close(stageDone)
		Pipe(From("a"), sendThenFail, out, pipeOpts(concurrency))
		return forward(out)
	}
}

// guardrailGrace is how long requireNone waits for a guardrail warning that
// must not come. It is generous on purpose: too short and the assertion
// degrades into a coin flip that passes against the pre-fix predicate. The
// RED runs against a reverted publishStageErr are what prove it is adequate.
const guardrailGrace = 500 * time.Millisecond

// TestPipe_InnerPipeFailureForwardedByStageIsDeliveredAndDoesNotWarn is the
// primary regression test for ENG-9014.
//
// Both production forwarding forms are covered, because both exist in modules
// today, and both the sequential and the parallel Pipe paths, because
// publishStageErr is deferred from each of them separately.
func TestPipe_InnerPipeFailureForwardedByStageIsDeliveredAndDoesNotWarn(t *testing.T) {
	forwards := []struct {
		name string
		fn   func(*P[string]) error
	}{
		{
			// `return out.Wait()`
			name: "ReturnWaitDirectly",
			fn:   func(out *P[string]) error { return out.Wait() },
		},
		{
			// `if err := out.Wait(); err != nil { return err }`
			name: "CheckWaitThenReturn",
			fn: func(out *P[string]) error {
				if err := out.Wait(); err != nil {
					return err
				}
				return nil
			},
		},
	}
	paths := []struct {
		name        string
		concurrency int
	}{
		{name: "Sequential", concurrency: 0},
		{name: "Parallel", concurrency: 4},
	}

	for _, fwd := range forwards {
		for _, path := range paths {
			t.Run(fwd.name+"/"+path.name, func(t *testing.T) {
				// captureWarnings uses the process-global default logger, so
				// no subtest here may call t.Parallel().
				warnings := captureWarnings(t)
				out := New[string]()
				stageDone := make(chan struct{})

				Pipe(
					From(1),
					innerFailureStage(path.concurrency, fwd.fn, stageDone),
					out,
					pipeOpts(path.concurrency),
				)

				got, err := out.Collect()

				require.Equal(t, []string{"item-a"}, got,
					"the inner Pipe's items must still reach the caller")
				require.ErrorIs(t, err, errInnerPipeFailure,
					"the stage error IS delivered: the inner Pipe recorded it on `out` "+
						"inside closeOnce.Do, so the caller's Wait() returns it")

				<-stageDone
				warnings.requireNone(t, guardrailGrace)
			})
		}
	}
}

// TestPipe_ResidualGapUnrelatedStageErrorIsSuppressedSilentlyAndThisIsDeliberate
// documents the one case the narrowed predicate deliberately does not catch.
//
// The inner Pipe records E1; the stage then returns an UNRELATED E2. E2 is
// suppressed — the caller observes E1 — and no warning is emitted, because the
// predicate's third clause (`recorded != nil`) cannot distinguish "the stage
// forwarded the recorded error" from "the stage substituted a different one".
//
// This is an accepted trade-off, not an oversight: no caller on this path
// substitutes or wraps the error today, and the obvious narrowing
// (`errors.Is(recorded, stageErr)`) is unsound — measured on go 1.25.8,
// errors.Is(u, u) is false for an uncomparable error value, and a bare `==`
// between two error interfaces panics when the dynamic types are identical and
// uncomparable. See uncomparable_error_test.go and publishStageErr's doc
// comment.
//
// It is pinned here so that a future change which alters this behavior — in
// either direction, delivering E2 or warning about it — fails loudly and has
// to revisit the trade-off on purpose rather than by accident.
func TestPipe_ResidualGapUnrelatedStageErrorIsSuppressedSilentlyAndThisIsDeliberate(t *testing.T) {
	warnings := captureWarnings(t)
	out := New[string]()
	stageDone := make(chan struct{})

	stage := func(_ int, out *P[string]) error {
		defer close(stageDone)
		// Inner Pipe wins out.closeOnce and records E1.
		Pipe(From("a"), sendThenFail, out)
		_ = out.Wait()
		// The stage reports something else entirely. E2 is not reachable.
		return errUnrelatedStageFailure
	}

	Pipe(From(1), stage, out)

	got, err := out.Collect()

	require.Equal(t, []string{"item-a"}, got)
	require.ErrorIs(t, err, errInnerPipeFailure,
		"the caller observes E1, the error the winning close recorded")
	require.NotErrorIs(t, err, errUnrelatedStageFailure,
		"E2 is suppressed: the close it would have been published through was "+
			"already consumed by the inner Pipe")

	<-stageDone
	warnings.requireNone(t, guardrailGrace)
}
