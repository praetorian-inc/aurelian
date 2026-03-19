// Package emitter provides a generic, channel-based primitive for building
// streaming pipelines. An P[T] wraps an unbuffered channel and a
// goroutine, enabling producers to emit items incrementally while consumers
// process them concurrently.
package pipeline

import (
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

// pipeSequential processes items one at a time, stopping immediately on error.
func pipeSequential[In, Out any](in *P[In], fn func(In, *P[Out]) error, out *P[Out], opts PipeOpts) {
	go func() {
		defer out.Close()
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
				out.err = err
				for range in.ch {
				}
				return
			}
			completed.Add(1)
		}
		inputDone.Store(true)
		if err := in.Wait(); err != nil && out.err == nil {
			out.err = err
		}
	}()
}

// pipeParallel processes items concurrently using an errgroup with the
// specified concurrency limit. The first error from any worker is captured,
// remaining input is drained so upstream doesn't block.
func pipeParallel[In, Out any](in *P[In], fn func(In, *P[Out]) error, out *P[Out], opts PipeOpts) {
	go func() {
		defer out.Close()
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
			g       errgroup.Group
			failed  atomic.Bool
			errOnce sync.Once
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
					errOnce.Do(func() { out.err = err })
					failed.Store(true)
					return err
				}
				completed.Add(1)
				return nil
			})
		}
		inputDone.Store(true)

		_ = g.Wait()

		if err := in.Wait(); err != nil && out.err == nil {
			out.err = err
		}
	}()
}
