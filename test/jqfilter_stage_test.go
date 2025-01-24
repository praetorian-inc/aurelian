package test

import (
	"bytes"
	"context"
	"testing"

	analyze "github.com/praetorian-inc/nebula/modules/analyze/aws"
	"github.com/praetorian-inc/nebula/pkg/stages"
	"github.com/praetorian-inc/nebula/pkg/types"
)

func TestJqFilter(t *testing.T) {

	testCases := []struct {
		name      string
		input     []byte
		filter    string
		expected  []byte
		expectErr bool
	}{
		{
			name:     "Valid filter",
			input:    []byte(`{"name": "John", "age": 30}`),
			filter:   ".age",
			expected: []byte("30"),
		},
		{
			name:     "Nonexistent field",
			input:    []byte(`{"name": "John", "age": 30}`),
			filter:   ".nonexistent",
			expected: []byte("null"),
		},
		{
			name:      "Invalid filter",
			input:     []byte(`{"name": "John", "age": 30}`),
			filter:    ".invalid",
			expectErr: false,
			expected:  []byte("null"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.WithValue(context.Background(), "metadata", analyze.AwsExpandActionsMetadata)
			opts := []*types.Option{}
			in := make(chan []byte, 1)
			in <- tc.input
			close(in)

			pipeline, err := stages.ChainStages[[]byte, []byte](
				stages.JqFilter(ctx, tc.filter),
				stages.AggregateOutput[[]byte],
			)
			if err != nil {
				t.Fatalf("Error chaining stages: %v", err)
			}

			for result := range pipeline(ctx, opts, in) {
				if tc.expectErr {
					if result != nil {
						t.Errorf("Expected an error, but got result: %s", result)
					}
				} else {
					if !bytes.Equal(result, tc.expected) {
						t.Errorf("Expected %s, but got %s", tc.expected, result)
					}
				}
			}
		})
	}
}
