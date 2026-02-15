//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	_ "github.com/praetorian-inc/aurelian/pkg/modules/aws/recon" // register modules
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAWSEC2Enumeration verifies comprehensive EC2 instance enumeration capabilities.
// This test validates:
// - EC2 instance discovery across regions
// - Correct resource identification and metadata extraction
// - Handling of multiple instances
// - Proper resource typing and classification
func TestAWSEC2Enumeration(t *testing.T) {
	fixture := NewFixture(t, "aws/list")
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
		AssertMinResults(t, results, 1)

		// Verify all expected instances are found
		instanceIDs := fixture.OutputList("instance_ids")
		require.NotEmpty(t, instanceIDs, "fixture should provide instance IDs")

		for _, id := range instanceIDs {
			AssertResultContainsString(t, results, id)
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

		// Parse CloudResource data from results
		raw, err := json.Marshal(results[0].Data)
		require.NoError(t, err)
		var resources []output.CloudResource
		require.NoError(t, json.Unmarshal(raw, &resources))

		// Filter to EC2 instances only
		var ec2Instances []output.CloudResource
		for _, r := range resources {
			if r.ResourceType == "AWS::EC2::Instance" {
				ec2Instances = append(ec2Instances, r)
			}
		}

		require.NotEmpty(t, ec2Instances, "should find EC2 instances")

		// Validate each instance has required fields
		instanceIDs := fixture.OutputList("instance_ids")
		for _, instance := range ec2Instances {
			// Verify basic resource metadata
			assert.NotEmpty(t, instance.ID, "instance should have ID")
			assert.NotEmpty(t, instance.ARN, "instance should have ARN")
			assert.Equal(t, "AWS::EC2::Instance", instance.ResourceType, "resource type should be EC2 Instance")
			assert.Equal(t, "AWS", instance.Platform, "platform should be AWS")
			assert.Equal(t, "us-east-2", instance.Region, "region should match scan target")

			// Verify instance is one of our test instances
			found := false
			for _, expectedID := range instanceIDs {
				if instance.ID == expectedID {
					found = true
					break
				}
			}
			assert.True(t, found, "instance ID %s should be in fixture outputs", instance.ID)

			// Verify properties contain expected fields
			assert.NotNil(t, instance.Properties, "instance should have properties")
			if props, ok := instance.Properties.(map[string]any); ok {
				// Common EC2 properties that should be present
				assert.Contains(t, props, "InstanceType", "should include instance type")
				assert.Contains(t, props, "ImageId", "should include AMI ID")
			}
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

		raw, err := json.Marshal(results[0].Data)
		require.NoError(t, err)
		var resources []output.CloudResource
		require.NoError(t, json.Unmarshal(raw, &resources))

		// Count EC2 instances
		ec2Count := 0
		for _, r := range resources {
			if r.ResourceType == "AWS::EC2::Instance" {
				ec2Count++
			}
		}

		// Terraform creates 2 instances
		expectedCount := len(fixture.OutputList("instance_ids"))
		assert.Equal(t, expectedCount, ec2Count, "should find exactly %d EC2 instances", expectedCount)
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

		raw, err := json.Marshal(results[0].Data)
		require.NoError(t, err)
		var resources []output.CloudResource
		require.NoError(t, json.Unmarshal(raw, &resources))

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
				assert.Equal(t, "AWS", r.Platform)
				assert.NotEmpty(t, r.ID)
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
		AssertResultContainsString(t, results, prefix)
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
	fixture := NewFixture(t, "aws/list")
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
			AssertResultContainsString(t, results, id)
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
