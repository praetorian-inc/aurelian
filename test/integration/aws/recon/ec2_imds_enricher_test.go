//go:build integration

package recon

import (
	"context"
	"os"
	"testing"

	_ "github.com/praetorian-inc/aurelian/pkg/modules/aws/enrichers" // register enrichers
	_ "github.com/praetorian-inc/aurelian/pkg/modules/aws/recon"     // register modules
	"github.com/praetorian-inc/aurelian/pkg/modules/common"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestEC2IMDSEnricher(t *testing.T) {
	fixture := testutil.NewFixture(t, "aws/recon/ec2-imds-check")
	fixture.Setup()

	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "list-all")
	if !ok {
		t.Fatal("list-all module not registered in plugin system")
	}

	// Run list-all with EC2 resource type (enricher auto-runs)
	results, err := mod.Run(plugin.Config{
		Args: map[string]any{
			"resource-type": []string{"AWS::EC2::Instance"},
			"regions":       []string{"us-east-1"},
			"scan-type":     "full",
		},
		Context: context.Background(),
	})
	require.NoError(t, err, "enumeration should succeed")
	testutil.AssertMinResults(t, results, 1)

	// Parse CloudResource data from results
	resources := flattenCloudResources(t, results[0].Data)

	// Build lookup sets from fixture outputs
	allInstanceIDs := fixture.OutputList("all_instance_ids")
	flaggedIDs := fixture.OutputList("flagged_instance_ids")
	safeIDs := fixture.OutputList("safe_instance_ids")
	require.NotEmpty(t, allInstanceIDs, "fixture should provide instance IDs")

	allIDSet := make(map[string]bool)
	for _, id := range allInstanceIDs {
		allIDSet[id] = true
	}
	flaggedIDSet := make(map[string]bool)
	for _, id := range flaggedIDs {
		flaggedIDSet[id] = true
	}
	safeIDSet := make(map[string]bool)
	for _, id := range safeIDs {
		safeIDSet[id] = true
	}

	// Filter to test instances
	var testInstances []output.CloudResource
	for _, r := range resources {
		if r.ResourceType == "AWS::EC2::Instance" && allIDSet[r.ResourceID] {
			testInstances = append(testInstances, r)
		}
	}
	require.Len(t, testInstances, len(allInstanceIDs), "should find all 3 test instances")

	// Assert enrichment: verify IMDS properties are present on each resource
	t.Run("enrichment adds IMDS properties", func(t *testing.T) {
		for _, instance := range testInstances {
			assert.Contains(t, instance.Properties, "MetadataHttpTokens",
				"instance %s should have MetadataHttpTokens", instance.ResourceID)
			assert.Contains(t, instance.Properties, "MetadataHttpEndpoint",
				"instance %s should have MetadataHttpEndpoint", instance.ResourceID)
			assert.Contains(t, instance.Properties, "InstanceStateName",
				"instance %s should have InstanceStateName", instance.ResourceID)
		}
	})

	// Assert YAML rule: Load rule and evaluate against each instance
	t.Run("YAML rule flags only non-compliant instances", func(t *testing.T) {
		ruleBytes, err := os.ReadFile("../../../../pkg/modules/aws/rules/ec2/ec2-imdsv1-enabled.yaml")
		require.NoError(t, err)

		var rule common.YAMLRule
		err = yaml.Unmarshal(ruleBytes, &rule)
		require.NoError(t, err)

		analyzer := common.NewYAMLAnalyzer([]common.YAMLRule{rule})

		for _, instance := range testInstances {
			analyzerResults, err := analyzer.Run(plugin.Config{
				Context: context.Background(),
				Args:    map[string]any{"resource": instance},
			})
			require.NoError(t, err)
			findings, ok := analyzerResults[0].Data.([]plugin.Finding)
			require.True(t, ok)

			if flaggedIDSet[instance.ResourceID] {
				assert.NotEmpty(t, findings,
					"instance %s (IMDSv1 allowed) should produce a finding", instance.ResourceID)
				if len(findings) > 0 {
					assert.Equal(t, "ec2-imdsv1-enabled", findings[0].RuleID)
					assert.Equal(t, "medium", findings[0].Severity)
				}
			} else if safeIDSet[instance.ResourceID] {
				assert.Empty(t, findings,
					"instance %s (safe) should not produce a finding", instance.ResourceID)
			}
		}
	})
}
