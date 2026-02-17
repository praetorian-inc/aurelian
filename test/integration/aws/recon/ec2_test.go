//go:build integration

package recon

import (
	"context"
	"encoding/json"
	"testing"

	_ "github.com/praetorian-inc/aurelian/pkg/modules/aws/recon" // register modules
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// flattenCloudResources converts results[0].Data (which is map[string][]CloudResource)
// into a flat slice of CloudResource for assertion convenience.
func flattenCloudResources(t *testing.T, data any) []output.CloudResource {
	t.Helper()
	raw, err := json.Marshal(data)
	require.NoError(t, err)
	var resourceMap map[string][]output.CloudResource
	require.NoError(t, json.Unmarshal(raw, &resourceMap), "Data should be map[string][]CloudResource")
	var all []output.CloudResource
	for _, resources := range resourceMap {
		all = append(all, resources...)
	}
	return all
}

// TestAWSEC2Enumeration verifies comprehensive EC2 instance enumeration capabilities.
func TestAWSEC2Enumeration(t *testing.T) {
	fixture := testutil.NewFixture(t, "aws/recon/list")
	fixture.Setup()

	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "list-all")
	if !ok {
		t.Fatal("list-all module not registered in plugin system")
	}

	t.Run("enumerates EC2 instances in single region", func(t *testing.T) {
		results, err := mod.Run(plugin.Config{
			Args: map[string]any{
				"resource-type": []string{"AWS::EC2::Instance"},
				"regions":       []string{"us-east-2"},
				"scan-type":     "full",
			},
			Context: context.Background(),
		})
		require.NoError(t, err, "enumeration should succeed")
		testutil.AssertMinResults(t, results, 1)

		// Verify all expected instances are found
		instanceIDs := fixture.OutputList("instance_ids")
		require.NotEmpty(t, instanceIDs, "fixture should provide instance IDs")

		for _, id := range instanceIDs {
			testutil.AssertResultContainsString(t, results, id)
		}
	})

	t.Run("validates EC2 instance metadata", func(t *testing.T) {
		results, err := mod.Run(plugin.Config{
			Args: map[string]any{
				"resource-type": []string{"AWS::EC2::Instance"},
				"regions":       []string{"us-east-2"},
				"scan-type":     "full",
			},
			Context: context.Background(),
		})
		require.NoError(t, err)
		require.NotEmpty(t, results, "should return results")

		// Parse CloudResource data from results — Data is map[string][]CloudResource keyed by region/type
		resources := flattenCloudResources(t, results[0].Data)

		// Filter to EC2 instances only
		var ec2Instances []output.CloudResource
		for _, r := range resources {
			if r.ResourceType == "AWS::EC2::Instance" {
				ec2Instances = append(ec2Instances, r)
			}
		}

		require.NotEmpty(t, ec2Instances, "should find EC2 instances")

		// Build set of fixture instance IDs for filtering
		instanceIDs := fixture.OutputList("instance_ids")
		instanceIDSet := make(map[string]bool)
		for _, id := range instanceIDs {
			instanceIDSet[id] = true
		}

		// Filter to only test instances (shared account may have others)
		var testInstances []output.CloudResource
		for _, instance := range ec2Instances {
			if instanceIDSet[instance.ResourceID] {
				testInstances = append(testInstances, instance)
			}
		}
		require.Len(t, testInstances, len(instanceIDs), "should find all fixture EC2 instances")

		// Validate each test instance has required fields
		for _, instance := range testInstances {
			assert.NotEmpty(t, instance.ResourceID, "instance should have ID")
			assert.NotEmpty(t, instance.ARN, "instance should have ARN")
			assert.Equal(t, "AWS::EC2::Instance", instance.ResourceType, "resource type should be EC2 Instance")
			assert.Equal(t, string(plugin.PlatformAWS), instance.Platform, "platform should be AWS")
			assert.Equal(t, "us-east-2", instance.Region, "region should match scan target")
			assert.NotNil(t, instance.Properties, "instance should have properties")
			assert.Contains(t, instance.Properties, "InstanceType", "should include instance type")
			assert.Contains(t, instance.Properties, "ImageId", "should include AMI ID")
		}
	})

	t.Run("enumerates instances with correct count", func(t *testing.T) {
		results, err := mod.Run(plugin.Config{
			Args: map[string]any{
				"resource-type": []string{"AWS::EC2::Instance"},
				"regions":       []string{"us-east-2"},
				"scan-type":     "full",
			},
			Context: context.Background(),
		})
		require.NoError(t, err)

		resources := flattenCloudResources(t, results[0].Data)

		// Count EC2 instances
		ec2Count := 0
		for _, r := range resources {
			if r.ResourceType == "AWS::EC2::Instance" {
				ec2Count++
			}
		}

		// Terraform creates 2 instances
		expectedCount := len(fixture.OutputList("instance_ids"))
		assert.GreaterOrEqual(t, ec2Count, expectedCount, "should find at least %d EC2 instances", expectedCount)
	})

	t.Run("handles empty results gracefully", func(t *testing.T) {
		// Test region without test resources
		results, err := mod.Run(plugin.Config{
			Args: map[string]any{
				"resource-type": []string{"AWS::EC2::Instance"},
				"regions":       []string{"us-west-1"}, // Different region
				"scan-type":     "full",
			},
			Context: context.Background(),
		})
		// Should not error even if no instances found
		require.NoError(t, err)
		// Results should still be valid (may be empty or contain other resources)
		require.NotNil(t, results)
	})

	t.Run("filters EC2 instances correctly from mixed resources", func(t *testing.T) {
		// Scan multiple resource types
		results, err := mod.Run(plugin.Config{
			Args: map[string]any{
				"resource-type": []string{
					"AWS::EC2::Instance",
					"AWS::S3::Bucket",
					"AWS::Lambda::Function",
				},
				"regions":   []string{"us-east-2"},
				"scan-type": "full",
			},
			Context: context.Background(),
		})
		require.NoError(t, err)
		require.NotEmpty(t, results)

		resources := flattenCloudResources(t, results[0].Data)

		// Verify we have multiple resource types
		resourceTypes := make(map[string]bool)
		for _, r := range resources {
			resourceTypes[r.ResourceType] = true
		}
		assert.True(t, len(resourceTypes) > 1, "should find multiple resource types")
		assert.True(t, resourceTypes["AWS::EC2::Instance"], "should include EC2 instances")

		// Verify each instance is properly typed
		for _, r := range resources {
			if r.ResourceType == "AWS::EC2::Instance" {
				assert.Equal(t, string(plugin.PlatformAWS), r.Platform)
				assert.NotEmpty(t, r.ResourceID)
			}
		}
	})

	t.Run("includes instance tags in enumeration", func(t *testing.T) {
		results, err := mod.Run(plugin.Config{
			Args: map[string]any{
				"resource-type": []string{"AWS::EC2::Instance"},
				"regions":       []string{"us-east-2"},
				"scan-type":     "full",
			},
			Context: context.Background(),
		})
		require.NoError(t, err)

		// Verify that the Name tag prefix from terraform is present
		prefix := fixture.Output("prefix")
		testutil.AssertResultContainsString(t, results, prefix)
	})

	t.Run("validates result metadata", func(t *testing.T) {
		results, err := mod.Run(plugin.Config{
			Args: map[string]any{
				"resource-type": []string{"AWS::EC2::Instance"},
				"regions":       []string{"us-east-2"},
				"scan-type":     "full",
			},
			Context: context.Background(),
		})
		require.NoError(t, err)
		require.NotEmpty(t, results)

		// Verify result metadata
		result := results[0]
		assert.NotNil(t, result.Metadata, "result should have metadata")
		assert.Equal(t, "list-all", result.Metadata["module"])
		assert.Equal(t, plugin.PlatformAWS, result.Metadata["platform"])

		regions, ok := result.Metadata["regions"].([]string)
		assert.True(t, ok, "regions should be string slice")
		assert.Contains(t, regions, "us-east-2")
	})
}

// TestAWSEC2EnumerationMultiRegion validates multi-region enumeration capabilities
func TestAWSEC2EnumerationMultiRegion(t *testing.T) {
	fixture := testutil.NewFixture(t, "aws/recon/list")
	fixture.Setup()

	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "list-all")
	if !ok {
		t.Fatal("list-all module not registered")
	}

	t.Run("enumerates across multiple regions", func(t *testing.T) {
		results, err := mod.Run(plugin.Config{
			Args: map[string]any{
				"resource-type": []string{"AWS::EC2::Instance"},
				"regions":       []string{"us-east-1", "us-east-2", "us-west-2"},
				"scan-type":     "full",
			},
			Context: context.Background(),
		})
		require.NoError(t, err)

		// Should include instances from us-east-2 (where test resources are)
		instanceIDs := fixture.OutputList("instance_ids")
		for _, id := range instanceIDs {
			testutil.AssertResultContainsString(t, results, id)
		}
	})

	t.Run("handles concurrent region scanning", func(t *testing.T) {
		// Test with high concurrency
		results, err := mod.Run(plugin.Config{
			Args: map[string]any{
				"resource-type": []string{"AWS::EC2::Instance"},
				"regions":       []string{"us-east-1", "us-east-2", "us-west-1", "us-west-2"},
				"scan-type":     "full",
				"concurrency":   10,
			},
			Context: context.Background(),
		})
		require.NoError(t, err)
		require.NotNil(t, results)
	})
}

// TestAWSEC2EnumerationErrorHandling validates error handling and edge cases
func TestAWSEC2EnumerationErrorHandling(t *testing.T) {
	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "list-all")
	if !ok {
		t.Fatal("list-all module not registered")
	}

	t.Run("handles invalid region gracefully", func(t *testing.T) {
		results, err := mod.Run(plugin.Config{
			Args: map[string]any{
				"resource-type": []string{"AWS::EC2::Instance"},
				"regions":       []string{"invalid-region-xyz"},
				"scan-type":     "full",
			},
			Context: context.Background(),
		})
		// Should either error or return empty results, not panic
		if err == nil {
			require.NotNil(t, results)
		}
	})

	t.Run("validates required parameters", func(t *testing.T) {
		// Missing resource-type should use defaults
		results, err := mod.Run(plugin.Config{
			Args: map[string]any{
				"regions":   []string{"us-east-2"},
				"scan-type": "full",
			},
			Context: context.Background(),
		})
		// Should succeed with default resource types
		require.NoError(t, err)
		require.NotNil(t, results)
	})

	t.Run("handles context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		_, err := mod.Run(plugin.Config{
			Args: map[string]any{
				"resource-type": []string{"AWS::EC2::Instance"},
				"regions":       []string{"us-east-2"},
				"scan-type":     "full",
			},
			Context: ctx,
		})
		// Should handle cancelled context appropriately
		// May error or return partial results depending on timing
		t.Logf("Cancellation result: %v", err)
	})
}
