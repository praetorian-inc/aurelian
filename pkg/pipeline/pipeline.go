// Package emitter provides a generic, channel-based primitive for building
// streaming pipelines. An P[T] wraps an unbuffered channel and a
// goroutine, enabling producers to emit items incrementally while consumers
// process them concurrently.
package pipeline

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"
)

// P[T] is a typed, channel-based producer. Producers call Send() to
// send items; consumers range over Range(). The underlying channel is
// unbuffered, providing natural backpressure.
type P[T any] struct {
	ch        chan T
	done      chan struct{}
	err       error
	closeOnce sync.Once
	sent      atomic.Int64
}

// New creates an P with an unbuffered channel.
func New[T any]() *P[T] {
	return &P[T]{
		ch:   make(chan T),
		done: make(chan struct{}),
	}
}

// From creates an P that emits all provided items in a goroutine, then
// closes itself. Useful for feeding a known collection into a pipeline.
func From[T any](items ...T) *P[T] {
	e := New[T]()
	go func() {
		defer e.Close()
		for _, item := range items {
			e.Send(item)
		}
	}()
	return e
}

// Send sends one item into the channel. Blocks until a consumer reads it.
func (e *P[T]) Send(item T) {
	e.ch <- item
	e.sent.Add(1)
}

// Sent returns the number of items sent through this pipeline.
func (e *P[T]) Sent() int64 {
	return e.sent.Load()
}

// Close signals that no more items will be emitted.
// It is safe to call multiple times.
func (e *P[T]) Close() {
	e.closeOnce.Do(func() {
		close(e.ch)
		close(e.done)
	})
}

// CloseWithError records err as the pipeline's error and then closes it, so a
// downstream Wait() observes the failure. Use it when a producer needs to
// propagate an error from a stage it consumed (e.g. a wrapped sub-pipeline)
// onto the pipeline it owns. A nil err is equivalent to Close. Like Close it is
// safe to call multiple times; only the first call takes effect.
func (e *P[T]) CloseWithError(err error) {
	_ = e.closeWithError(err)
}

// closeWithError is CloseWithError, reporting whether this call is the one that
// closed the pipeline (and therefore the one whose error was recorded). A later
// call returns false and changes nothing.
func (e *P[T]) closeWithError(err error) bool {
	won := false
	e.closeOnce.Do(func() {
		e.err = err
		close(e.ch)
		close(e.done)
		won = true
	})
	return won
}

// Wait blocks until the producer signals completion and returns its error.
func (e *P[T]) Wait() error {
	<-e.done
	return e.err
}

// Range returns the underlying channel for use in for-range loops.
func (e *P[T]) Range() <-chan T {
	return e.ch
}

// Drain consumes and discards all items in a background goroutine, then
// blocks until the pipeline closes and returns any upstream error.
func (e *P[T]) Drain() error {
	go func() {
		for range e.ch {
		}
	}()
	return e.Wait()
}

// Collect drains the pipeline into a slice and returns it along with any
// pipeline error. It blocks until the producer closes the pipeline.
func (e *P[T]) Collect() ([]T, error) {
	var items []T
	for item := range e.ch {
		items = append(items, item)
	}
	return items, e.Wait()
}

// PipeOpts configures optional behavior for Pipe.
type PipeOpts struct {
	Concurrency int
	Progress    func(completed, total int64) // called periodically with stage progress
}

// startProgressTicker starts a background goroutine that periodically calls
// the progress callback with the stage's completed and total counters.
// When inputDone is false, total is reported as negative to signal that the
// denominator is still growing (the Logger uses this to cap display at 99%).
func startProgressTicker(completed, total *atomic.Int64, inputDone *atomic.Bool, progress func(int64, int64)) func() {
	if progress == nil {
		return func() {}
	}
	ticker := time.NewTicker(500 * time.Millisecond)
	done := make(chan struct{})
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				fin := inputDone.Load()
				c := completed.Load()
				t := total.Load()
				if !fin && t > 0 {
					t = -t
				}
				progress(c, t)
			case <-done:
				return
			}
		}
	}()
	return func() { close(done) }
}

// Pipe reads from in, calls fn for each item (which must send into out), and
// closes out when in is drained. Runs in a goroutine. Errors from fn or from
// the upstream producer are propagated to out.Wait().
//
// When opts is provided with Concurrency > 1, items are processed concurrently
// using an errgroup with the specified concurrency limit. The first error from
// any worker is captured and remaining input is drained.
func Pipe[In, Out any](in *P[In], fn func(In, *P[Out]) error, out *P[Out], opts ...*PipeOpts) {
	var opt PipeOpts
	if len(opts) > 0 && opts[0] != nil {
		opt = *opts[0]
	}

	if opt.Concurrency > 1 {
		pipeParallel(in, fn, out, opt)
	} else {
		pipeSequential(in, fn, out, opt)
	}
}

// publishStageErr closes out, recording stageErr as out's error.
//
// CloseWithError sets out.err inside out.closeOnce.Do, before close(out.done),
// so a caller blocked in out.Wait() is guaranteed to observe the error. That
// edge only exists while the Pipe that owns out is the one that closes it: if a
// stage function handed the caller-owned out to an inner Pipe, the inner Pipe's
// deferred close consumed closeOnce first and this call is a no-op — the error
// is dropped, and nothing downstream can ever see it. That is a structural
// ownership bug in the caller, so say so loudly rather than losing it silently.
//
// The close itself reports which case this is: closeWithError returns true only
// for the call that won closeOnce, and therefore only for the call whose error
// was recorded. Nothing here inspects out.err or compares error values.
func publishStageErr[T any](out *P[T], stageErr error) {
	if out.closeWithError(stageErr) || stageErr == nil {
		return
	}
	slog.Warn("pipeline: stage error dropped — the output pipeline was already "+
		"closed by another owner, so this error can never reach the caller; "+
		"the stage must forward through a pipeline it owns instead of handing "+
		"the caller's pipeline to an inner Pipe",
		"error", stageErr)
}

// pipeSequential processes items one at a time, stopping immediately on error.
func pipeSequential[In, Out any](in *P[In], fn func(In, *P[Out]) error, out *P[Out], opts PipeOpts) {
	go func() {
		// stageErr is published via CloseWithError rather than written to
		// out.err directly: CloseWithError records the error INSIDE
		// out.closeOnce.Do, before close(out.done), which is the
		// happens-before edge a caller's Wait() needs. A direct write to
		// out.err has no such edge and is lost (and racy) whenever something
		// else has already closed out.
		var stageErr error
		defer func() { publishStageErr(out, stageErr) }()
		var completed, total atomic.Int64
		var inputDone atomic.Bool
		stop := startProgressTicker(&completed, &total, &inputDone, opts.Progress)
		defer func() {
			stop()
			if opts.Progress != nil {
				// Final update with positive total (input is done), then remove.
				opts.Progress(completed.Load(), total.Load())
				opts.Progress(-1, -1)
			}
		}()
		for item := range in.ch {
			total.Add(1)
			if err := fn(item, out); err != nil {
				stageErr = err
				for range in.ch {
				}
				return
			}
			completed.Add(1)
		}
		inputDone.Store(true)
		if err := in.Wait(); err != nil && stageErr == nil {
			stageErr = err
		}
	}()
}

// pipeParallel processes items concurrently using an errgroup with the
// specified concurrency limit. The first error from any worker is captured,
// remaining input is drained so upstream doesn't block.
func pipeParallel[In, Out any](in *P[In], fn func(In, *P[Out]) error, out *P[Out], opts PipeOpts) {
	go func() {
		// See pipeSequential: the stage error is captured in a local and
		// published via CloseWithError so it carries a happens-before edge to
		// the caller's Wait(). g.Wait() supplies the edge between the workers'
		// returns and this goroutine's read of the first error.
		var stageErr error
		defer func() { publishStageErr(out, stageErr) }()
		var completed, total atomic.Int64
		var inputDone atomic.Bool
		stop := startProgressTicker(&completed, &total, &inputDone, opts.Progress)
		defer func() {
			stop()
			if opts.Progress != nil {
				opts.Progress(completed.Load(), total.Load())
				opts.Progress(-1, -1)
			}
		}()

		var (
			g      errgroup.Group
			failed atomic.Bool
		)
		g.SetLimit(opts.Concurrency)

		for item := range in.ch {
			if failed.Load() {
				for range in.ch {
				}
				break
			}
			total.Add(1)
			g.Go(func() error {
				if err := fn(item, out); err != nil {
					failed.Store(true)
					return err
				}
				completed.Add(1)
				return nil
			})
		}
		inputDone.Store(true)

		// errgroup already holds the first non-nil worker error behind its own
		// sync.Once; this replaces the previous errOnce/out.err write.
		stageErr = g.Wait()

		if err := in.Wait(); err != nil && stageErr == nil {
			stageErr = err
		}
	}()
}
