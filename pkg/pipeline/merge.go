package pipeline

import "sync"

// Merge fans multiple input pipelines into a single output pipeline.
// It starts a goroutine per input that forwards items into out.
// The output is closed once all inputs are drained.
// If any input carries an error, the first error is propagated to out.
func Merge[T any](inputs ...*P[T]) *P[T] {
	out := New[T]()

	if len(inputs) == 0 {
		go out.Close()
		return out
	}

	var (
		wg      sync.WaitGroup
		errOnce sync.Once
	)
	for _, in := range inputs {
		wg.Add(1)
		go func(p *P[T]) {
			defer wg.Done()
			for item := range p.ch {
				out.Send(item)
			}
			if err := p.Wait(); err != nil {
				errOnce.Do(func() { out.err = err })
			}
		}(in)
	}

	go func() {
		wg.Wait()
		out.Close()
	}()

	return out
}
