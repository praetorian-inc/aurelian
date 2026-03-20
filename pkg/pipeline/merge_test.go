package pipeline

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMerge_CombinesItems(t *testing.T) {
	a := From(1, 2, 3)
	b := From(4, 5, 6)

	merged := Merge(a, b)
	items, err := merged.Collect()
	require.NoError(t, err)
	assert.ElementsMatch(t, []int{1, 2, 3, 4, 5, 6}, items)
}

func TestMerge_SingleInput(t *testing.T) {
	a := From("x", "y")
	merged := Merge(a)
	items, err := merged.Collect()
	require.NoError(t, err)
	assert.Equal(t, []string{"x", "y"}, items)
}

func TestMerge_EmptyInputs(t *testing.T) {
	a := From[int]()
	b := From[int]()
	merged := Merge(a, b)
	items, err := merged.Collect()
	require.NoError(t, err)
	assert.Empty(t, items)
}

func TestMerge_PropagatesError(t *testing.T) {
	sentinel := errors.New("upstream failure")

	// Build a pipeline that errors: From → Pipe (errors) → errored
	in := From(1)
	errored := New[int]()
	Pipe(in, func(v int, out *P[int]) error {
		return sentinel
	}, errored)

	good := From(42)
	merged := Merge(errored, good)
	_, err := merged.Collect()
	assert.ErrorIs(t, err, sentinel)
}

func TestMerge_NoInputs(t *testing.T) {
	merged := Merge[int]()
	items, err := merged.Collect()
	require.NoError(t, err)
	assert.Empty(t, items)
}

func TestMerge_RaceSafety(t *testing.T) {
	// Spin up many inputs sending concurrently to verify no race conditions.
	const numInputs = 10
	const itemsPerInput = 100

	inputs := make([]*P[int], numInputs)
	for i := range inputs {
		inputs[i] = New[int]()
	}

	merged := Merge(inputs...)

	// Start all producers concurrently.
	for i, p := range inputs {
		go func(p *P[int], base int) {
			defer p.Close()
			for j := 0; j < itemsPerInput; j++ {
				p.Send(base + j)
			}
		}(p, i*itemsPerInput)
	}

	items, err := merged.Collect()
	require.NoError(t, err)
	assert.Len(t, items, numInputs*itemsPerInput)
}
