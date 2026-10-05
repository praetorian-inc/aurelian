//go:build integration

package enumeration

import (
	"testing"
	"time"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSFNStateMachineEnumerator_Integration(t *testing.T) {
	profiles := []struct {
		name    string
		profile string
		regions []string
	}{
		{name: "sandbox-read-only", profile: "sandbox-read-only", regions: []string{"us-east-1", "us-east-2", "us-west-2"}},
		{name: "nb-read-only", profile: "nb-read-only", regions: []string{"us-east-1", "us-east-2", "us-west-2"}},
	}

	for _, p := range profiles {
		t.Run(p.name, func(t *testing.T) {
			opts := plugin.AWSCommonRecon{
				Regions:     p.regions,
				Concurrency: len(p.regions),
			}
			opts.Profile = p.profile
			provider := NewAWSConfigProvider(opts)
			enum := NewSFNStateMachineEnumerator(opts, provider, NewSkipReport())

			t.Run("EnumerateAll returns state machines with RoleArn", func(t *testing.T) {
				results, err := collectSFNResults(func(out *pipeline.P[output.AWSResource]) error {
					return enum.EnumerateAll(out)
				})
				require.NoError(t, err)

				t.Logf("profile=%s: found %d state machines across %v", p.profile, len(results), p.regions)
				for _, r := range results {
					assert.Equal(t, "AWS::StepFunctions::StateMachine", r.ResourceType)
					assert.NotEmpty(t, r.ARN)
					assert.NotEmpty(t, r.AccountRef)
					assert.NotEmpty(t, r.Region)
					assert.NotEmpty(t, r.ResourceID)
					t.Logf("  %s (role=%s)", r.ARN, r.Properties["RoleArn"])
				}

				if len(results) > 0 {
					for _, r := range results {
						roleArn, _ := r.Properties["RoleArn"].(string)
						assert.NotEmpty(t, roleArn,
							"RoleArn must be populated for %s — this is the whole point of the native enumerator", r.ARN)
					}
				}
			})

			t.Run("EnumerateByARN round-trips", func(t *testing.T) {
				allResults, err := collectSFNResults(func(out *pipeline.P[output.AWSResource]) error {
					return enum.EnumerateAll(out)
				})
				require.NoError(t, err)

				if len(allResults) == 0 {
					t.Skipf("profile=%s: no state machines found, skipping EnumerateByARN test", p.profile)
				}

				target := allResults[0]
				arnResults, err := collectSFNResults(func(out *pipeline.P[output.AWSResource]) error {
					return enum.EnumerateByARN(target.ARN, out)
				})
				require.NoError(t, err)
				require.Len(t, arnResults, 1)
				assert.Equal(t, target.ARN, arnResults[0].ARN)
				assert.Equal(t, target.ResourceID, arnResults[0].ResourceID)
				assert.Equal(t, target.Properties["RoleArn"], arnResults[0].Properties["RoleArn"])
			})
		})
	}
}

func TestSFNStateMachineEnumerator_Perf(t *testing.T) {
	profiles := []struct {
		name    string
		profile string
		regions []string
	}{
		{name: "sandbox-read-only", profile: "sandbox-read-only", regions: []string{"us-east-1", "us-east-2", "us-west-2"}},
		{name: "nb-read-only", profile: "nb-read-only", regions: []string{"us-east-1", "us-east-2", "us-west-2"}},
	}

	for _, p := range profiles {
		t.Run(p.name, func(t *testing.T) {
			opts := plugin.AWSCommonRecon{
				Regions:     p.regions,
				Concurrency: len(p.regions),
			}
			opts.Profile = p.profile
			provider := NewAWSConfigProvider(opts)
			enum := NewSFNStateMachineEnumerator(opts, provider, NewSkipReport())

			t.Run("EnumerateAll perf", func(t *testing.T) {
				start := time.Now()
				results, err := collectSFNResults(func(out *pipeline.P[output.AWSResource]) error {
					return enum.EnumerateAll(out)
				})
				elapsed := time.Since(start)

				require.NoError(t, err)
				t.Logf("profile=%s: EnumerateAll found %d state machines in %s (%d regions)",
					p.profile, len(results), elapsed, len(p.regions))
				assert.Less(t, elapsed, 60*time.Second,
					"EnumerateAll should complete within 60s across %d regions", len(p.regions))
			})

			t.Run("EnumerateByARN perf", func(t *testing.T) {
				allResults, err := collectSFNResults(func(out *pipeline.P[output.AWSResource]) error {
					return enum.EnumerateAll(out)
				})
				require.NoError(t, err)

				if len(allResults) == 0 {
					t.Skipf("profile=%s: no state machines found, skipping perf test", p.profile)
				}

				target := allResults[0]
				start := time.Now()
				results, err := collectSFNResults(func(out *pipeline.P[output.AWSResource]) error {
					return enum.EnumerateByARN(target.ARN, out)
				})
				elapsed := time.Since(start)

				require.NoError(t, err)
				require.Len(t, results, 1)
				t.Logf("profile=%s: EnumerateByARN for %s in %s", p.profile, target.ARN, elapsed)
				assert.Less(t, elapsed, 5*time.Second,
					"EnumerateByARN for a single ARN should complete within 5s")
			})
		})
	}
}

func collectSFNResults(run func(out *pipeline.P[output.AWSResource]) error) ([]output.AWSResource, error) {
	out := pipeline.New[output.AWSResource]()
	resultCh := make(chan []output.AWSResource, 1)
	go func() {
		var results []output.AWSResource
		for r := range out.Range() {
			results = append(results, r)
		}
		resultCh <- results
	}()
	err := run(out)
	out.Close()
	return <-resultCh, err
}
