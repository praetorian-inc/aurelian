package pipeline

import (
	"errors"
	"fmt"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEmitter_BasicProduceConsume(t *testing.T) {
	e := From(0, 1, 2, 3, 4)

	var got []int
	for v := range e.Range() {
		got = append(got, v)
	}

	require.NoError(t, e.Wait())
	assert.Equal(t, []int{0, 1, 2, 3, 4}, got)
}

func TestEmitter_ErrorPropagation(t *testing.T) {
	e := New[int]()
	go func() {
		e.Send(1)
		e.err = fmt.Errorf("producer failed")
		e.Close()
	}()

	for range e.Range() {
	}

	require.Error(t, e.Wait())
}

func TestPipe(t *testing.T) {
	in := From(1, 2, 3)
	out := New[string]()

	Pipe(in, func(v int, o *P[string]) error {
		o.Send(fmt.Sprintf("item-%d", v))
		return nil
	}, out)

	got, err := out.Collect()
	require.NoError(t, err)
	assert.Equal(t, []string{"item-1", "item-2", "item-3"}, got)
}

func TestPipe_FnError(t *testing.T) {
	in := From(0, 1, 2, 3, 4, 5, 6, 7, 8, 9)
	out := New[int]()

	Pipe(in, func(v int, o *P[int]) error {
		if v == 3 {
			return fmt.Errorf("bad value")
		}
		o.Send(v * 2)
		return nil
	}, out)

	got, err := out.Collect()
	require.Error(t, err)
	assert.Len(t, got, 3)
}

func TestPipe_UpstreamErrorPropagates(t *testing.T) {
	in := New[int]()
	out := New[int]()

	go func() {
		in.Send(1)
		in.err = fmt.Errorf("upstream failed")
		in.Close()
	}()

	Pipe(in, func(v int, o *P[int]) error {
		o.Send(v)
		return nil
	}, out)

	_, err := out.Collect()
	require.Error(t, err)
}

func TestFrom_Empty(t *testing.T) {
	e := From[int]()

	got, err := e.Collect()
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestPipe_Parallel_ProcessesAllItems(t *testing.T) {
	in := From(1, 2, 3, 4, 5)
	out := New[int]()

	Pipe(in, func(item int, o *P[int]) error {
		o.Send(item * 2)
		return nil
	}, out, &PipeOpts{Concurrency: 3})

	results, err := out.Collect()
	require.NoError(t, err)

	sort.Ints(results)
	assert.Equal(t, []int{2, 4, 6, 8, 10}, results)
}

func TestPipe_Parallel_RespectsConcurrencyLimit(t *testing.T) {
	in := From(1, 2, 3, 4, 5, 6, 7, 8)
	out := New[int]()

	var active atomic.Int32
	var maxActive atomic.Int32

	concurrency := 2
	Pipe(in, func(item int, o *P[int]) error {
		cur := active.Add(1)
		// Track the maximum number of concurrent workers.
		for {
			old := maxActive.Load()
			if cur <= old || maxActive.CompareAndSwap(old, cur) {
				break
			}
		}
		// Simulate work so goroutines overlap.
		time.Sleep(50 * time.Millisecond)
		active.Add(-1)
		o.Send(item)
		return nil
	}, out, &PipeOpts{Concurrency: concurrency})

	results, err := out.Collect()
	require.NoError(t, err)
	assert.Len(t, results, 8)
	assert.LessOrEqual(t, int32(maxActive.Load()), int32(concurrency))
}

func TestPipe_Parallel_PropagatesErrors(t *testing.T) {
	in := From(1, 2, 3, 4, 5)
	out := New[int]()

	expectedErr := errors.New("processing failed")

	Pipe(in, func(item int, o *P[int]) error {
		if item == 3 {
			return expectedErr
		}
		o.Send(item)
		return nil
	}, out, &PipeOpts{Concurrency: 2})

	_, err := out.Collect()
	require.Error(t, err)
	assert.Equal(t, expectedErr, err)
}

func TestPipe_Parallel_DefaultsConcurrencyToOne(t *testing.T) {
	in := From(1, 2, 3)
	out := New[int]()

	var active atomic.Int32
	var maxActive atomic.Int32

	Pipe(in, func(item int, o *P[int]) error {
		cur := active.Add(1)
		for {
			old := maxActive.Load()
			if cur <= old || maxActive.CompareAndSwap(old, cur) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		active.Add(-1)
		o.Send(item)
		return nil
	}, out, &PipeOpts{Concurrency: 1}) // concurrency 1 = serial path

	results, err := out.Collect()
	require.NoError(t, err)
	assert.Len(t, results, 3)
	assert.Equal(t, int32(1), maxActive.Load())
}
