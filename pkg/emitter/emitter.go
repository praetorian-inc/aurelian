// Package emitter provides a generic, channel-based primitive for building
// streaming pipelines. An Emitter[T] wraps an unbuffered channel and a
// goroutine, enabling producers to emit items incrementally while consumers
// process them concurrently.
package emitter

// Emitter[T] is a typed, channel-based producer. Producers call Emit() to
// send items; consumers range over Range(). The underlying channel is
// unbuffered, providing natural backpressure.
type Emitter[T any] struct {
	ch   chan T
	done chan struct{}
	err  error
}

// New creates an Emitter with an unbuffered channel.
func New[T any]() *Emitter[T] {
	return &Emitter[T]{
		ch:   make(chan T),
		done: make(chan struct{}),
	}
}

// From creates an Emitter that emits all provided items in a goroutine, then
// closes itself. Useful for feeding a known collection into a pipeline.
func From[T any](items ...T) *Emitter[T] {
	e := New[T]()
	go func() {
		defer e.Close()
		for _, item := range items {
			e.Emit(item)
		}
	}()
	return e
}

// Emit sends one item into the channel. Blocks until a consumer reads it.
func (e *Emitter[T]) Emit(item T) {
	e.ch <- item
}

// Close signals that no more items will be emitted. Must be called exactly
// once by the producer when it is finished.
func (e *Emitter[T]) Close() {
	close(e.ch)
	close(e.done)
}

// CloseWithError signals completion with an error. Must be called exactly
// once by the producer when it is finished.
func (e *Emitter[T]) CloseWithError(err error) {
	e.err = err
	close(e.ch)
	close(e.done)
}

// Wait blocks until the producer signals completion and returns its error.
func (e *Emitter[T]) Wait() error {
	<-e.done
	return e.err
}

// Range returns the underlying channel for use in for-range loops.
func (e *Emitter[T]) Range() <-chan T {
	return e.ch
}

// Pipe reads from in, calls fn for each item (which may emit into out), and
// closes out when in is drained. Runs in a goroutine. Errors from fn or from
// the upstream producer are propagated to out.Wait().
func Pipe[In, Out any](in *Emitter[In], out *Emitter[Out], fn func(In, *Emitter[Out]) error) {
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
