package pipeline

import (
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

var errCloseSentinel = errors.New("close sentinel failure")

// TestCloseWithError_VisibleToAReaderAlreadyParkedInWait pins the ordering
// property that makes CloseWithError the right primitive for publishStageErr.
//
// A reader parked on <-done is released by close(done). CloseWithError records
// err INSIDE closeOnce.Do, before close(done), so the write happens-before the
// release and the reader is guaranteed to see it. The test deliberately does
// NOT synchronise the reader into its parked state: both interleavings — reader
// parks first, or closer wins first — must yield the sentinel. There is no
// schedule in which Wait() returns nil after a CloseWithError(err). That
// "no such schedule" is the whole contract.
func TestCloseWithError_VisibleToAReaderAlreadyParkedInWait(t *testing.T) {
	p := New[int]()

	got := make(chan error, 1)
	go func() { got <- p.Wait() }()

	p.CloseWithError(errCloseSentinel)

	require.ErrorIs(t, <-got, errCloseSentinel,
		"a reader released by close(done) must observe the error recorded before it")
}

// TestCloseWithError_IsAtomicWhenRacingAnotherCloser is the test that a bare
// `p.err = err` followed by `p.Close()` could not pass, and is the reason
// publishStageErr calls CloseWithError instead.
//
// Two owners race to close the same pipeline while several readers call Wait().
// Because the error write lives inside closeOnce.Do, exactly one closer wins and
// every reader observes the SAME value — all nil, or all sentinel. With the
// error written outside the once, the write would be unsynchronised with the
// readers' loads: the race detector reports it, and readers could disagree.
//
// Run this under -race; without -race it still asserts observer agreement, but
// the data-race half of the contract goes unchecked.
func TestCloseWithError_IsAtomicWhenRacingAnotherCloser(t *testing.T) {
	const (
		rounds  = 50
		readers = 4
	)

	for range rounds {
		p := New[int]()

		observed := make(chan error, readers)
		for range readers {
			go func() { observed <- p.Wait() }()
		}

		var closers sync.WaitGroup
		closers.Add(2)
		go func() { defer closers.Done(); p.CloseWithError(errCloseSentinel) }()
		go func() { defer closers.Done(); p.Close() }()
		closers.Wait()

		first := <-observed
		if first != nil {
			require.ErrorIs(t, first, errCloseSentinel)
		}
		for range readers - 1 {
			require.Equal(t, first, <-observed,
				"every reader must observe the same outcome; the error is published "+
					"inside closeOnce.Do, so there is no window where observers disagree")
		}
	}
}
