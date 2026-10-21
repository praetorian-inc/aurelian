package pipeline

import (
	"errors"
	"fmt"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var (
	errParallelWorker   = errors.New("parallel worker failure")
	errParallelUpstream = errors.New("parallel upstream failure")
)

// parallelOpts is the shape production takes: Run's extractor stage sets
// Concurrency, and the default is 5. Anything > 1 routes Pipe to pipeParallel.
func parallelOpts() *PipeOpts { return &PipeOpts{Concurrency: 5} }

// TestPipe_Parallel_OwnedShapeDeliversWorkerErrorToWait is the parallel twin of
// TestPipe_StageErrorWithPrivateInnerPipeline: a stage that forwards through a
// pipeline it owns and Sends into `out` itself, so only the outer Pipe ever
// closes `out`.
//
// The happens-before edge here has two links, and both are real: the failing
// worker's return is ordered before g.Wait() returns (errgroup's own
// synchronisation), and g.Wait()'s result is published through
// CloseWithError inside closeOnce.Do, before close(done), which is ordered
// before the caller's Wait() returns. Run under -race.
func TestPipe_Parallel_OwnedShapeDeliversWorkerErrorToWait(t *testing.T) {
	out := New[string]()

	stage := func(n int, out *P[string]) error {
		private := New[string]()
		Pipe(From(fmt.Sprintf("item-%d", n)), forward, private)
		for v := range private.Range() {
			out.Send(v)
		}
		if err := private.Wait(); err != nil {
			return err
		}
		if n == 3 {
			return errParallelWorker
		}
		return nil
	}

	Pipe(From(1, 2, 3, 4, 5), stage, out, parallelOpts())

	got, err := out.Collect()
	require.ErrorIs(t, err, errParallelWorker,
		"a worker error must reach the caller's Wait() through the owned shape")

	// How many items arrive is deliberately not asserted: once a worker fails,
	// pipeParallel stops feeding the rest, so the count is schedule-dependent.
	// Two things must hold regardless of schedule. Every item that did arrive
	// is well-formed:
	for _, v := range got {
		require.True(t, slices.Contains(
			[]string{"item-1", "item-2", "item-3", "item-4", "item-5"}, v),
			"unexpected item %q", v)
	}
	// And the failing worker's own item IS among them. The stage emits through
	// the owned pipeline and only then returns the sentinel, so a failing stage
	// still publishes the work it completed first. That partial-results-plus-
	// error shape is the point of carrying the error on the pipeline rather
	// than discarding the stream: a caller gets both.
	require.Contains(t, got, "item-3",
		"work the failing stage completed before returning must still be delivered")
}

// TestPipe_Parallel_OwnedShapeSucceedsCleanly separates "the error is lost"
// from "ownership breaks the parallel path": the same owned shape, every stage
// returning nil, must deliver all items, a nil Wait(), and no guardrail
// warning.
func TestPipe_Parallel_OwnedShapeSucceedsCleanly(t *testing.T) {
	warnings := captureWarnings(t)
	out := New[string]()

	stage := func(n int, out *P[string]) error {
		private := New[string]()
		Pipe(From(fmt.Sprintf("item-%d", n)), forward, private)
		for v := range private.Range() {
			out.Send(v)
		}
		return private.Wait()
	}

	Pipe(From(1, 2, 3, 4, 5), stage, out, parallelOpts())

	got, err := out.Collect()
	require.NoError(t, err)
	slices.Sort(got)
	require.Equal(t,
		[]string{"item-1", "item-2", "item-3", "item-4", "item-5"}, got)

	warnings.requireNone(t, 200*time.Millisecond)
}

// TestPipe_Parallel_PropagatesUpstreamProducerError covers the parallel path's
// upstream branch (`in.Wait()` after g.Wait()). The sequential path has had
// this covered; the parallel path had not, even though it is the path
// production takes. Every stage succeeds, so the only error available is the
// producer's.
func TestPipe_Parallel_PropagatesUpstreamProducerError(t *testing.T) {
	in := New[int]()
	go func() {
		in.Send(1)
		in.Send(2)
		in.CloseWithError(errParallelUpstream)
	}()

	out := New[int]()
	Pipe(in, func(item int, o *P[int]) error {
		o.Send(item)
		return nil
	}, out, parallelOpts())

	got, err := out.Collect()
	require.ErrorIs(t, err, errParallelUpstream,
		"an upstream producer error must survive the parallel path")
	slices.Sort(got)
	require.Equal(t, []int{1, 2}, got,
		"the items produced before the failure are still delivered")
}

// TestPipe_Parallel_StopsInvokingStageAfterAWorkerFails covers pipeParallel's
// early-abort branch: once a worker has failed, remaining input is drained
// rather than submitted, so the stage stops running. For a scanner stage that
// means no further AWS calls after the first failure.
//
// The producer withholds the tail until the failing worker has returned its
// error, so the abort flag is set before the tail is offered. One caveat is
// stated rather than hidden: the flag is stored by pipeParallel's wrapper just
// AFTER the stage function returns, so the very first tail item can in
// principle be received before the store becomes visible. That window is a few
// instructions wide against a channel handoff per item, so the assertion is
// "at least one tail item was skipped" over a tail of 64 — it cannot be made
// exactly deterministic through the public API, and asserting an exact count
// would be asserting the scheduler.
func TestPipe_Parallel_StopsInvokingStageAfterAWorkerFails(t *testing.T) {
	const tail = 64

	in := New[int]()
	returned := make(chan struct{})
	var invoked atomic.Int64

	go func() {
		defer in.Close()
		in.Send(0) // the item whose worker fails
		<-returned // withhold the tail until that failure has been returned
		for i := 1; i <= tail; i++ {
			in.Send(i)
		}
	}()

	out := New[int]()
	Pipe(in, func(item int, o *P[int]) error {
		invoked.Add(1)
		if item == 0 {
			close(returned)
			return errParallelWorker
		}
		o.Send(item)
		return nil
	}, out, parallelOpts())

	_, err := out.Collect()
	require.ErrorIs(t, err, errParallelWorker)
	require.Less(t, invoked.Load(), int64(1+tail),
		"after a worker failed, remaining input must be drained rather than "+
			"handed to the stage function")
}
