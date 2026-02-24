// Package emitter provides a generic, channel-based primitive for building
// streaming pipelines. An Pipeline[T] wraps an unbuffered channel and a
// goroutine, enabling producers to emit items incrementally while consumers
// process them concurrently.
package pipeline

// Pipeline[T] is a typed, channel-based producer. Producers call Send() to
// send items; consumers range over Range(). The underlying channel is
// unbuffered, providing natural backpressure.
type Pipeline[T any] struct {
	ch   chan T
	done chan struct{}
	err  error
}

// New creates an Pipeline with an unbuffered channel.
func New[T any]() *Pipeline[T] {
	return &Pipeline[T]{
		ch:   make(chan T),
		done: make(chan struct{}),
	}
}

// From creates an Pipeline that emits all provided items in a goroutine, then
// closes itself. Useful for feeding a known collection into a pipeline.
func From[T any](items ...T) *Pipeline[T] {
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
func (e *Pipeline[T]) Send(item T) {
	e.ch <- item
}

// Close signals that no more items will be emitted. Must be called exactly
// once by the producer when it is finished.
func (e *Pipeline[T]) Close() {
	close(e.ch)
	close(e.done)
}

// Wait blocks until the producer signals completion and returns its error.
func (e *Pipeline[T]) Wait() error {
	<-e.done
	return e.err
}

// Range returns the underlying channel for use in for-range loops.
func (e *Pipeline[T]) Range() <-chan T {
	return e.ch
}

// Pipe reads from in, calls fn for each item (which must send into out), and
// closes out when in is drained. Runs in a goroutine. Errors from fn or from
// the upstream producer are propagated to out.Wait().
func Pipe[In, Out any](in *Pipeline[In], fn func(In, *Pipeline[Out]) error, out *Pipeline[Out]) {
	go func() {
		defer out.Close()
		for item := range in.ch {
			if err := fn(item, out); err != nil {
				out.err = err
				// Drain remaining input so upstream doesn't block.
				for range in.ch {
				}
				return
			}
		}
		// Propagate upstream errors.
		if err := in.Wait(); err != nil && out.err == nil {
			out.err = err
		}
	}()
}
