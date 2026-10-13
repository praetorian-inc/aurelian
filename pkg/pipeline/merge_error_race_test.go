package pipeline

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// erroringInput returns a pipeline that emits n items and then closes with err.
// Merge's forwarder observes that error via p.Wait() and performs the
// errOnce.Do(func() { out.err = err }) write under test.
func erroringInput(n int, err error) *P[int] {
	p := New[int]()
	go func() {
		for i := range n {
			p.Send(i)
		}
		p.CloseWithError(err)
	}()
	return p
}

func goodInput(n int) *P[int] {
	p := New[int]()
	go func() {
		defer p.Close()
		for i := range n {
			p.Send(i)
		}
	}()
	return p
}

// TestMerge_ErrorWriteRacesConcurrentWaiters hammers the happens-before edge
// that Merge relies on to publish out.err:
//
//	forwarder writes out.err -> wg.Done() -> wg.Wait() returns ->
//	out.Close() -> close(out.done) -> reader's Wait() returns -> reads out.err
//
// Many concurrent readers block in merged.Wait() while a separate goroutine
// drains the merged channel, so every reader's read of out.err is released at
// the same instant the closer publishes. If the WaitGroup edge did not exist,
// -race would flag the write/read pair.
func TestMerge_ErrorWriteRacesConcurrentWaiters(t *testing.T) {
	sentinel := errors.New("input failure")

	const iterations = 100
	const waiters = 8

	for iter := range iterations {
		// The erroring input sends nothing so its forwarder reaches the
		// out.err write as early as possible, maximising the overlap with
		// readers already parked in Wait().
		inputs := []*P[int]{
			erroringInput(0, sentinel),
			goodInput(16),
			goodInput(16),
		}
		merged := Merge(inputs...)

		var ready, done sync.WaitGroup
		errs := make([]error, waiters)
		for w := range waiters {
			ready.Add(1)
			done.Add(1)
			go func() {
				defer done.Done()
				ready.Done()
				errs[w] = merged.Wait()
			}()
		}
		// Make sure the waiters are actually in flight before anything drains,
		// so Wait() is contending with the forwarders rather than running after.
		ready.Wait()
		runtime.Gosched()

		var drained int
		for range merged.Range() {
			drained++
		}
		done.Wait()

		require.Equal(t, 32, drained, "iteration %d: lost items", iter)
		for w := range waiters {
			require.ErrorIsf(t, errs[w], sentinel,
				"iteration %d: waiter %d observed %v, error was lost", iter, w, errs[w])
		}
		require.ErrorIs(t, merged.Wait(), sentinel, "iteration %d: late Wait lost the error", iter)
	}
}

// TestMerge_ErrorWriteContendingForwarders drives several forwarders into the
// errOnce.Do write simultaneously while readers wait, exercising both the
// sync.Once contention and the WaitGroup edge.
func TestMerge_ErrorWriteContendingForwarders(t *testing.T) {
	const iterations = 100
	const erroring = 6

	for iter := range iterations {
		sentinels := make([]error, erroring)
		inputs := make([]*P[int], 0, erroring+2)
		for i := range erroring {
			sentinels[i] = fmt.Errorf("input %d failed", i)
			inputs = append(inputs, erroringInput(0, sentinels[i]))
		}
		inputs = append(inputs, goodInput(8), goodInput(8))

		merged := Merge(inputs...)

		var done sync.WaitGroup
		waiterErr := make([]error, 4)
		for w := range waiterErr {
			done.Add(1)
			go func() {
				defer done.Done()
				waiterErr[w] = merged.Wait()
			}()
		}

		items, err := merged.Collect()
		done.Wait()

		require.Len(t, items, 16, "iteration %d", iter)
		require.Errorf(t, err, "iteration %d: error dropped entirely", iter)
		// Whichever forwarder won errOnce, every observer must see that same error.
		for w, we := range waiterErr {
			require.Equalf(t, err, we,
				"iteration %d: waiter %d saw %v but Collect saw %v", iter, w, we, err)
		}
		assert.Containsf(t, sentinels, err, "iteration %d: unexpected error %v", iter, err)
	}
}

// TestMerge_ErrorSurvivesSlowDrain delays the drain so the forwarders finish,
// the closer runs wg.Wait()+Close(), and the reader's Wait() happens strictly
// afterwards. This is the lost-error shape: if out.err were published without
// an edge into close(done), a late reader could still see nil.
func TestMerge_ErrorSurvivesSlowDrain(t *testing.T) {
	sentinel := errors.New("late failure")

	const iterations = 200
	for iter := range iterations {
		merged := Merge(erroringInput(0, sentinel), goodInput(1))

		items, err := merged.Collect()
		require.Lenf(t, items, 1, "iteration %d", iter)
		require.ErrorIsf(t, err, sentinel, "iteration %d: error lost", iter)
	}
}

// TestMerge_UnsafeIfOutputClosedByAnotherOwner demonstrates what happens when a
// caller violates Merge's documented ownership precondition by closing the
// merged pipeline itself.
//
// Merge owns the pipeline it returns and is the only thing that may close it.
// When a foreign owner closes it first, that close consumes out.closeOnce, so
// the publication Merge performs after wg.Wait() is a no-op: the merged error
// is DROPPED and no reader can ever observe it. Wait() returns nil even though
// an input failed.
//
// The drop is deterministic, not a race. Merge records the first input error
// into a local firstErr inside errOnce.Do and publishes it once from the closer
// goroutine after wg.Wait(); the WaitGroup orders every write before that read,
// so there is no unsynchronised out.err access to detect. Running this probe
// under -race passes. What it proves is a correctness loss, not a data race:
//
//	observed error after foreign close: <nil>   (an input failed with a sentinel)
//
// The loss is also announced. Merge publishes through publishStageErr, whose
// guardrail logs a WARN naming the error it could not deliver, so this misuse
// is loud at run time rather than silent. The test asserts that WARN as well as
// the nil, which is what makes it a check on the guardrail's coverage of the
// Merge shape and not merely a record of the bug.
//
// The WARN must be awaited, not polled. The foreign Close releases the reader's
// Wait() immediately, so the test body finishes before the closer goroutine has
// even reached publishStageErr — a buffer read after Wait() returns is a race
// that is usually lost. captureWarnings/next (ownership_test.go) block for the
// record; that is the same timing shape as the Pipe ownership tests, and the
// same helpers apply unchanged.
//
// This shape is NOT reachable from any current caller (the sole production
// caller, pkg/modules/azure/recon/find_secrets.go, uses the merged pipeline
// only as the INPUT to a Pipe, and Pipe never closes its input).
//
// It stays opt-in because it deliberately performs the API misuse that Merge's
// doc comment forbids: it is a demonstration of a contract violation, not a
// behaviour the library promises, so it does not belong in the default suite.
// Run it with MERGE_UNSAFE_PROBE=1.
func TestMerge_UnsafeIfOutputClosedByAnotherOwner(t *testing.T) {
	if os.Getenv("MERGE_UNSAFE_PROBE") != "1" {
		t.Skip("set MERGE_UNSAFE_PROBE=1 to run the deliberately-unsafe ownership probe")
	}

	warnings := captureWarnings(t)

	sentinel := errors.New("forwarder failure")

	// No items are sent, so the foreign Close() cannot panic a Send; this
	// isolates the publication path. The gate holds the input open until the
	// foreign close has certainly won closeOnce, which is what makes the drop
	// deterministic rather than schedule-dependent.
	gate := make(chan struct{})
	in := New[int]()
	go func() {
		<-gate
		in.CloseWithError(sentinel)
	}()

	merged := Merge(in)

	// A foreign owner closes the merged output before the forwarder has
	// observed its input's error -- the ownership violation.
	merged.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	var observed error
	go func() {
		defer wg.Done()
		observed = merged.Wait() // released immediately by the foreign Close
	}()

	close(gate) // the forwarder can now observe sentinel via in.Wait()
	wg.Wait()

	t.Logf("observed error after foreign close: %v (input failed with %v)", observed, sentinel)

	assert.NoError(t, observed,
		"the foreign close consumed closeOnce, so the merged error cannot reach a reader")

	// Blocks until the guardrail fires; the drop must not be silent.
	assertDroppedStageErrWarning(t, warnings.next(t), sentinel)
}
