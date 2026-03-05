// Package emitter provides a generic, channel-based primitive for building
// streaming pipelines. An P[T] wraps an unbuffered channel and a
// goroutine, enabling producers to emit items incrementally while consumers
// process them concurrently.
package pipeline

import (
	"sync"
	"sync/atomic"

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

// Collect drains the pipeline into a slice and returns it along with any
// pipeline error. It blocks until the producer closes the pipeline.
func (e *P[T]) Collect() ([]T, error) {
	var items []T
	for item := range e.ch {
		items = append(items, item)
	}
	return items, e.Wait()
}

// Opts configures optional behavior for Pipe.
type PipeOpts struct {
	Concurrency int
}

// Pipe reads from in, calls fn for each item (which must send into out), and
// closes out when in is drained. Runs in a goroutine. Errors from fn or from
// the upstream producer are propagated to out.Wait().
//
// When opts is provided with Concurrency > 1, items are processed concurrently
// using an errgroup with the specified concurrency limit. The first error from
// any worker is captured and remaining input is drained.
func Pipe[In, Out any](in *P[In], fn func(In, *P[Out]) error, out *P[Out], opts ...*PipeOpts) {
	concurrency := 1
	if len(opts) > 0 && opts[0] != nil && opts[0].Concurrency > 1 {
		concurrency = opts[0].Concurrency
	}

	if concurrency > 1 {
		pipeParallel(in, fn, out, concurrency)
	} else {
		pipeSequential(in, fn, out)
	}
}

// pipeSequential processes items one at a time, stopping immediately on error.
func pipeSequential[In, Out any](in *P[In], fn func(In, *P[Out]) error, out *P[Out]) {
	go func() {
		defer out.Close()
		for item := range in.ch {
			if err := fn(item, out); err != nil {
				out.err = err
				for range in.ch {
				}
				return
			}
		}
		if err := in.Wait(); err != nil && out.err == nil {
			out.err = err
		}
	}()
}

// pipeParallel processes items concurrently using an errgroup with the
// specified concurrency limit. The first error from any worker is captured,
// remaining input is drained so upstream doesn't block.
func pipeParallel[In, Out any](in *P[In], fn func(In, *P[Out]) error, out *P[Out], concurrency int) {
	go func() {
		defer out.Close()

		var (
			g       errgroup.Group
			failed  atomic.Bool
			errOnce sync.Once
		)
		g.SetLimit(concurrency)

		for item := range in.ch {
			if failed.Load() {
				for range in.ch {
				}
				break
			}
			g.Go(func() error {
				if err := fn(item, out); err != nil {
					errOnce.Do(func() { out.err = err })
					failed.Store(true)
					return err
				}
				return nil
			})
		}

		g.Wait()

		if err := in.Wait(); err != nil && out.err == nil {
			out.err = err
		}
	}()
}
