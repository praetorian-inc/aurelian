package pipeline

import "sync"

// Merge fans multiple input pipelines into a single output pipeline.
// It starts a goroutine per input that forwards items into out.
// The output is closed once all inputs are drained.
// If any input carries an error, the first error is propagated to out.
//
// Ownership: Merge owns the pipeline it returns and is the only thing that
// may close it. Callers must treat the returned pipeline strictly as an
// INPUT — range it, Collect it, Drain it, or hand it to a Pipe as the `in`
// argument. Never hand it to a Pipe (or anything else that closes what it
// writes to) as the `out` argument, and never Close it yourself: whichever
// close runs first wins the pipeline's closeOnce, so a foreign close would
// discard the merged error before Merge could publish it, and nothing
// downstream could ever observe the failure.
func Merge[T any](inputs ...*P[T]) *P[T] {
	out := New[T]()

	if len(inputs) == 0 {
		go out.Close()
		return out
	}

	var (
		wg      sync.WaitGroup
		errOnce sync.Once
		// firstErr is written only inside errOnce.Do, which runs before the
		// writing forwarder's deferred wg.Done(); the closer reads it only
		// after wg.Wait() returns. WaitGroup gives Done happens-before Wait,
		// so that read is ordered after every write.
		firstErr error
	)
	for _, in := range inputs {
		wg.Add(1)
		go func(p *P[T]) {
			defer wg.Done()
			for item := range p.ch {
				out.Send(item)
			}
			if err := p.Wait(); err != nil {
				errOnce.Do(func() { firstErr = err })
			}
		}(in)
	}

	go func() {
		wg.Wait()
		// Publish via publishStageErr rather than writing out.err directly: it
		// records the error INSIDE out.closeOnce.Do, before close(out.done),
		// which is the happens-before edge a caller's Wait() needs, and it warns
		// if some other owner closed out first — the ownership violation the doc
		// comment forbids, which would otherwise discard firstErr silently. A nil
		// firstErr is equivalent to Close and emits nothing.
		publishStageErr(out, firstErr)
	}()

	return out
}
