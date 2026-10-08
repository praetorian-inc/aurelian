//go:build integration

package recon

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const lastModifiedTestRegion = "us-east-2"

// TestAWSFindSecretsLastModified checks, against the real find-secrets
// fixture, that each timestamp-stamped type is emitted by list-all with a
// plausible LastModified and an unchanged identity.
func TestAWSFindSecretsLastModified(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/find-secrets")
	fixture.Setup()

	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "list-all")
	require.True(t, ok, "list-all module not registered in plugin system")

	// Lower bound: well before any fixture could exist. Upper bound: now plus
	// small clock skew between this host and AWS.
	floor := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	const skew = 5 * time.Minute

	cases := []struct {
		resourceType string
		// match picks the fixture's resource out of the listing and asserts
		// its identity fields.
		match func(t *testing.T, r output.AWSResource) bool
	}{
		{
			resourceType: "AWS::EC2::Instance",
			match: func(t *testing.T, r output.AWSResource) bool {
				return r.ResourceID == fixture.Output("instance_id")
			},
		},
		{
			resourceType: "AWS::Logs::LogGroup",
			match: func(t *testing.T, r output.AWSResource) bool {
				return r.ResourceID == fixture.Output("log_group_name")
			},
		},
		{
			// State machines are enumerated natively (LAB-7141), so ResourceID
			// is the name and the ARN is the identity Guard keys on.
			resourceType: "AWS::StepFunctions::StateMachine",
			match: func(t *testing.T, r output.AWSResource) bool {
				if r.ARN != fixture.Output("state_machine_arn") {
					return false
				}
				arn := fixture.Output("state_machine_arn")
				name := arn[strings.LastIndex(arn, ":")+1:]
				assert.Equal(t, name, r.ResourceID, "state machine ResourceID must be its name")
				assert.NotEmpty(t, r.Properties["RoleArn"], "the native enumerator must still capture RoleArn")
				return true
			},
		},
		{
			resourceType: "AWS::SSM::Document",
			match: func(t *testing.T, r output.AWSResource) bool {
				return r.ResourceID == fixture.Output("ssm_document_name")
			},
		},
		{
			resourceType: "AWS::ECS::TaskDefinition",
			match: func(t *testing.T, r output.AWSResource) bool {
				return r.ARN == fixture.Output("task_definition_arn")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.resourceType, func(t *testing.T) {
			results, err := testutil.RunAndCollect(t, mod, plugin.Config{
				Args: map[string]any{
					"resource-type": []string{tc.resourceType},
					"regions":       []string{lastModifiedTestRegion},
					"scan-type":     "full",
				},
				Context: context.Background(),
			})
			require.NoError(t, err)

			var found []output.AWSResource
			for _, r := range awsResources(results) {
				if tc.match(t, r) {
					found = append(found, r)
				}
			}
			require.Len(t, found, 1, "expected exactly one listed %s for the fixture (%d resources listed)", tc.resourceType, len(results))
			r := found[0]

			lastModified := "<nil>"
			if r.LastModified != nil {
				lastModified = r.LastModified.UTC().Format(time.RFC3339Nano)
			}
			t.Logf("%s ResourceID=%q ARN=%q LastModified=%s", tc.resourceType, r.ResourceID, r.ARN, lastModified)

			assert.Equal(t, tc.resourceType, r.ResourceType)
			require.NotNil(t, r.LastModified, "fixture %s must carry LastModified", tc.resourceType)
			assert.True(t, r.LastModified.After(floor), "LastModified %s must be after %s", lastModified, floor.Format(time.RFC3339))
			assert.False(t, r.LastModified.After(time.Now().Add(skew)), "LastModified %s must not be in the future", lastModified)
		})
	}
}

// TestAWSFindSecretsLogsSince checks that logs-since bounds only CloudWatch
// Logs reading: an old cutoff still finds the fixture's log secret, a future
// cutoff hides it, and SSM Parameter findings are unaffected by either.
func TestAWSFindSecretsLogsSince(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/find-secrets")
	fixture.Setup()

	logGroup := fixture.Output("log_group_name")
	ssmParameter := fixture.Output("ssm_parameter_name")

	// Log events expire with 1-day retention; re-inject so the positive case
	// has something to find.
	testutil.EnsureLogEvent(t, lastModifiedTestRegion,
		logGroup,
		fixture.Output("log_stream_name"),
		fixture.Output("log_event_message"),
	)

	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "find-secrets")
	require.True(t, ok, "find-secrets module not registered in plugin system")

	run := func(t *testing.T, logsSince time.Time) []output.AurelianRisk {
		t.Helper()
		results, err := testutil.RunAndCollect(t, mod, plugin.Config{
			Args: map[string]any{
				"regions":       []string{lastModifiedTestRegion},
				"resource-type": []string{"AWS::Logs::LogGroup", "AWS::SSM::Parameter"},
				"max-events":    10000,
				"max-streams":   10,
				"logs-since":    logsSince.UTC().Format(time.RFC3339),
				// A fresh Titus DB per run so one run's findings cannot
				// suppress or leak into the other's.
				"db-path": filepath.Join(t.TempDir(), "titus.db"),
			},
			Context: context.Background(),
		})
		require.NoError(t, err)

		var risks []output.AurelianRisk
		for _, m := range results {
			if r, ok := m.(output.AurelianRisk); ok {
				risks = append(risks, r)
			}
		}
		for _, r := range risks {
			t.Logf("logs-since=%s risk %s on %s", logsSince.UTC().Format(time.RFC3339), r.Name, r.ImpactedResourceID)
		}
		return risks
	}

	t.Run("cutoff 30 days ago still reads the fixture's log event", func(t *testing.T) {
		risks := run(t, time.Now().Add(-30*24*time.Hour))
		assert.True(t, hasRiskForIdentifier(risks, logGroup), "expected a risk for log group %s", logGroup)
		assert.True(t, hasRiskForIdentifier(risks, ssmParameter), "expected a risk for SSM parameter %s", ssmParameter)
	})

	// now+7h minus the 6h lag buffer puts FilterLogEvents' StartTime an hour
	// in the future, so no log event can qualify.
	t.Run("future cutoff reads no log events but other types are still scanned", func(t *testing.T) {
		risks := run(t, time.Now().Add(7*time.Hour))
		assert.False(t, hasRiskForIdentifier(risks, logGroup), "log group %s must yield no risk when logs-since is in the future", logGroup)
		assert.True(t, hasRiskForIdentifier(risks, ssmParameter), "logs-since must not affect SSM parameter %s", ssmParameter)
	})
}

func awsResources(results []model.AurelianModel) []output.AWSResource {
	var out []output.AWSResource
	for _, m := range results {
		switch r := m.(type) {
		case output.AWSResource:
			out = append(out, r)
		case *output.AWSResource:
			out = append(out, *r)
		}
	}
	return out
}
