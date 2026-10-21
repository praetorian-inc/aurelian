package pipeline

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// uncomparableErr is an error whose DYNAMIC TYPE is uncomparable: a struct
// with a slice field, reached through a VALUE receiver on Error().
//
// Both halves are load-bearing. The slice field is what makes the struct
// uncomparable — Go's == on structs compares fields, and slices are not
// comparable. The VALUE receiver is what puts that struct type itself into the
// error interface's type word; with a POINTER receiver the dynamic type would
// be *uncomparableErr, which is a pointer and therefore always comparable, and
// every test below would pass vacuously against a buggy implementation.
//
// Comparing two `error` interface values compiles unconditionally — the
// operands are interfaces, so the compiler cannot know the dynamic type. The
// check happens at run time, and when both dynamic types are identical and
// uncomparable the runtime panics:
//
//	panic: runtime error: comparing uncomparable type pipeline.uncomparableErr
//
// That is why a library may not compare two arbitrary error values it did not
// create. A stage error is caller-supplied: it can legitimately be any type
// satisfying error, including this one. Measured behaviour of `==` on two
// `error` values:
//
//	same uncomparable value, self-compare   PANIC
//	two distinct uncomparable, same type    PANIC
//	uncomparable vs *errors.errorString     ok (type words differ)
//	comparable pointers (fmt.Errorf)        ok
//
// The self-compare row is the dangerous one, because it is the SUCCESS path:
// when the stage error is published normally, the pipeline's recorded error IS
// the stage error, so a diagnostic that compares the two panics on every
// error-carrying Pipe whose stage returned an uncomparable error.
type uncomparableErr struct{ notes []string }

func (e uncomparableErr) Error() string { return "uncomparable: " + strings.Join(e.notes, ",") }

// assertCarriesUncomparable asserts that err is the uncomparableErr carrying
// the given notes.
//
// A panic anywhere in the pipeline's goroutines takes down the whole test
// binary, which is itself the failure signal for the comparison bug — no
// recover() plumbing is needed or wanted. But asserting on the error VALUE
// matters independently: it makes these tests fail loudly if the error is
// merely DROPPED (Wait() returning nil) rather than panicking, which is the
// other way this code path can break.
func assertCarriesUncomparable(t *testing.T, err error, notes ...string) {
	t.Helper()

	require.Error(t, err, "the uncomparable stage error must reach the caller, not be dropped")

	var target uncomparableErr
	require.True(t, errors.As(err, &target),
		"Wait() must surface the uncomparableErr itself, got %T: %v", err, err)
	assert.Equal(t, notes, target.notes,
		"the error that surfaced must be the one the stage returned, not a substitute")
}

// TestUncomparableStageError_Sequential covers a sequential Pipe stage (default
// opts, Concurrency 0) returning an error whose dynamic type is uncomparable.
//
// pipeSequential captures it in stageErr and publishes it through
// publishStageErr, which wins out's closeOnce — so out's recorded error and
// stageErr are the same interface value. Any diagnostic that compares those two
// values panics here.
func TestUncomparableStageError_Sequential(t *testing.T) {
	stageErr := uncomparableErr{notes: []string{"sequential", "stage"}}

	out := New[int]()
	Pipe(From(1, 2, 3), func(_ int, _ *P[int]) error {
		return stageErr
	}, out)

	items, err := out.Collect()

	assertCarriesUncomparable(t, err, "sequential", "stage")
	assert.Empty(t, items, "the stage emitted nothing before failing")
}

// TestUncomparableStageError_Parallel covers the same stage failure on the
// parallel path (Concurrency > 1), where the error travels through errgroup
// before publishStageErr sees it. errgroup holds the first non-nil worker error
// behind its own sync.Once and returns that same interface value from g.Wait(),
// so the identity that makes the self-comparison panic survives the trip.
func TestUncomparableStageError_Parallel(t *testing.T) {
	stageErr := uncomparableErr{notes: []string{"parallel", "stage"}}

	out := New[int]()
	Pipe(From(1, 2, 3, 4, 5, 6, 7, 8), func(_ int, _ *P[int]) error {
		return stageErr
	}, out, &PipeOpts{Concurrency: 4})

	items, err := out.Collect()

	assertCarriesUncomparable(t, err, "parallel", "stage")
	assert.Empty(t, items, "every worker failed, so nothing was emitted")
}

// TestUncomparableStageError_FromUpstream covers the upstream path: the stage
// function itself always succeeds, and the uncomparable error arrives via
// in.Wait() after the input channel drains.
//
// This is a distinct route into stageErr from the two above — the error is
// assigned from in.Wait() rather than returned by fn — and it is the one a
// stage-only test would miss. It then reaches the same publication point, so it
// panics the same way.
func TestUncomparableStageError_FromUpstream(t *testing.T) {
	upstreamErr := uncomparableErr{notes: []string{"upstream", "input"}}

	in := New[int]()
	go func() {
		in.Send(1)
		in.Send(2)
		in.CloseWithError(upstreamErr)
	}()

	out := New[int]()
	Pipe(in, func(item int, o *P[int]) error {
		o.Send(item * 10)
		return nil
	}, out)

	items, err := out.Collect()

	assertCarriesUncomparable(t, err, "upstream", "input")
	assert.Equal(t, []int{10, 20}, items,
		"the stage succeeded on every item, so its output must still arrive")
}

// TestUncomparableStageError_ThroughMerge covers an uncomparable error carried
// by one of Merge's inputs.
//
// Merge publishes firstErr through publishStageErr too, so it shares the same
// publication point as a Pipe stage and is exposed to the same hazard: the
// error it hands over is caller-supplied and may be of any type. Merge is a
// distinct route in — the error comes from a forwarder's p.Wait() under
// errOnce, not from a stage function or from a Pipe's in.Wait() — so it needs
// its own case rather than being assumed covered by the Pipe tests.
func TestUncomparableStageError_ThroughMerge(t *testing.T) {
	mergeErr := uncomparableErr{notes: []string{"merge", "input"}}

	failing := New[int]()
	go func() {
		failing.Send(1)
		failing.CloseWithError(mergeErr)
	}()

	healthy := New[int]()
	go func() {
		defer healthy.Close()
		healthy.Send(2)
	}()

	merged := Merge(failing, healthy)

	items, err := merged.Collect()

	assertCarriesUncomparable(t, err, "merge", "input")
	assert.ElementsMatch(t, []int{1, 2}, items,
		"both inputs' items must still be forwarded before the error is published")
}

// TestUncomparableStageError_PipeOfMergeDoesNotPanic chains the two: a Merge
// whose failing input carries an uncomparable error feeds a Pipe, so the error
// passes through publishStageErr TWICE in one run — once for the merged
// pipeline, then again for the Pipe's own output after in.Wait() surfaces it.
//
// This is the shape a real module uses (fan in, then transform), and it is
// where a comparison at either publication point is fatal.
func TestUncomparableStageError_PipeOfMergeDoesNotPanic(t *testing.T) {
	mergeErr := uncomparableErr{notes: []string{"merge", "then", "pipe"}}

	failing := New[int]()
	go func() {
		defer failing.CloseWithError(mergeErr)
		failing.Send(1)
	}()

	healthy := New[int]()
	go func() {
		defer healthy.Close()
		healthy.Send(2)
	}()

	out := New[string]()
	Pipe(Merge(failing, healthy), func(item int, o *P[string]) error {
		o.Send(strings.Repeat("x", item))
		return nil
	}, out)

	items, err := out.Collect()

	assertCarriesUncomparable(t, err, "merge", "then", "pipe")
	assert.Len(t, items, 2, "both forwarded items must be transformed before the error surfaces")
}
