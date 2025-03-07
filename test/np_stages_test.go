package test

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	reconaws "github.com/praetorian-inc/nebula/modules/recon/aws"
	options "github.com/praetorian-inc/nebula/pkg/links/opts"
	"github.com/praetorian-inc/nebula/pkg/stages"
	"github.com/praetorian-inc/nebula/pkg/types"
)

func TestNoseyParkerEnumeratorStage(t *testing.T) {
	testCases := []struct {
		name      string
		input     []types.NpInput
		match     string
		expectErr bool
	}{
		{
			name: "Valid input",
			input: []types.NpInput{
				{
					ContentBase64: base64.StdEncoding.EncodeToString([]byte(`token=ghp_AbcdEfGHiJKlm6nopNPqrxK3UvWx1yzAbc1D`)),
					Provenance: types.NpProvenance{
						ResourceType: "testType1",
						ResourceID:   "testID1",
						Region:       "testRegion1",
						AccountID:    "testAccountID1",
					},
				},
			},
			match:     "GitHub Personal Access Token",
			expectErr: false,
		},
		{
			name: "Valid input",
			input: []types.NpInput{
				{
					Content: `token=ghp_AbcdEfGHiJKlm6nopNPqrxK3UvWx1yzAbc1D`,
					Provenance: types.NpProvenance{
						ResourceType: "testType2",
						ResourceID:   "testID2",
						Region:       "testRegion2",
						AccountID:    "testAccountID2",
					},
				},
			},
			match:     "GitHub Personal Access Token",
			expectErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			ctx := context.WithValue(context.Background(), "metadata", reconaws.AwsFindSecretsMetadata)
			ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()

			opts := reconaws.AwsFindSecretsOptions
			for _, opt := range opts {
				if opt.Name == options.OutputOpt.Name {
					opt.Value = t.TempDir()
				}
			}

			in := make(chan types.NpInput, len(tc.input))
			for _, input := range tc.input {
				in <- input
			}
			close(in)

			out := stages.NoseyParkerEnumeratorStage(ctx, opts, in)

			for result := range out {
				if result == "" {
					t.Errorf("Expected non-empty result, but got empty result")
				}

				if tc.expectErr {
					t.Errorf("Expected an error, but got result: %s", result)
				} else {
					if result == "" {
						t.Errorf("Expected non-empty result, but got empty result")
					}

					t.Logf("Result: %s", result)

					if tc.match != "" && !strings.Contains(result, tc.match) {
						t.Errorf("Expected result to contain %s, but got %s", tc.match, result)
					}
				}
			}

		})
	}
}
