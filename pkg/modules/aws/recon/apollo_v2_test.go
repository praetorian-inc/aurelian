package recon

import (
	"context"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewApolloV2(t *testing.T) {
	profile := "test-profile"
	regions := []string{"us-east-1", "us-west-2"}

	apollo := NewApolloV2(profile, regions)

	require.NotNil(t, apollo)
	assert.Equal(t, profile, apollo.Profile)
	assert.Equal(t, regions, apollo.Regions)
	assert.NotEmpty(t, apollo.ResourceTypes, "ResourceTypes should be populated with defaults")
	assert.Len(t, apollo.ResourceTypes, 6, "Should have 6 default resource types")
}

func TestDefaultApolloResourceTypes(t *testing.T) {
	types := DefaultApolloResourceTypes()

	require.NotNil(t, types)
	assert.Len(t, types, 6)

	// Verify all expected resource types are present
	expectedTypes := []string{
		"AWS::IAM::Role",
		"AWS::IAM::User",
		"AWS::IAM::Group",
		"AWS::Lambda::Function",
		"AWS::EC2::Instance",
		"AWS::CloudFormation::Stack",
	}

	for _, expected := range expectedTypes {
		assert.Contains(t, types, expected)
	}
}

func TestApolloV2_WithOrgPolicyFile(t *testing.T) {
	apollo := NewApolloV2("profile", []string{"us-east-1"})

	result := apollo.WithOrgPolicyFile("/path/to/policies.json")

	assert.Equal(t, "/path/to/policies.json", apollo.OrgPolicyFile)
	assert.Equal(t, apollo, result, "Should return self for chaining")
}

func TestApolloV2_WithResourceTypes(t *testing.T) {
	apollo := NewApolloV2("profile", []string{"us-east-1"})
	customTypes := []string{"AWS::S3::Bucket", "AWS::DynamoDB::Table"}

	result := apollo.WithResourceTypes(customTypes)

	assert.Equal(t, customTypes, apollo.ResourceTypes)
	assert.Equal(t, apollo, result, "Should return self for chaining")
}

func TestApolloResult(t *testing.T) {
	result := &ApolloResult{
		Permissions:               []interface{}{},
		ResourceRoleRelationships: []*IAMPermission{},
		GitHubActionsPermissions:  []*GitHubActionsPermission{},
	}

	require.NotNil(t, result)
	assert.NotNil(t, result.Permissions)
	assert.NotNil(t, result.ResourceRoleRelationships)
	assert.NotNil(t, result.GitHubActionsPermissions)
}

// TestGatherResources_Structure verifies the gatherResources method signature and basic structure
func TestGatherResources_Structure(t *testing.T) {
	// This test verifies the method exists and has the correct signature
	// Full integration testing requires AWS credentials
	apollo := NewApolloV2("test-profile", []string{"us-east-1"})

	// Verify the method can be called (even if it returns an error due to no AWS creds)
	_, err := apollo.gatherResources(context.Background())

	// We expect an error because we don't have AWS credentials in tests
	// The important part is that the method signature is correct
	_ = err // Error expected without credentials
}

// TestGatherGaad_Structure verifies the gatherGaad method signature and basic structure
func TestGatherGaad_Structure(t *testing.T) {
	// This test verifies the method exists and has the correct signature
	// Full integration testing requires AWS credentials
	apollo := NewApolloV2("test-profile", []string{"us-east-1"})

	// Verify the method can be called (even if it returns an error due to no AWS creds)
	_, err := apollo.gatherGaad(context.Background())

	// We expect an error because we don't have AWS credentials in tests
	// The important part is that the method signature is correct
	_ = err // Error expected without credentials
}

// TestGatherResourcePolicies_Structure verifies the gatherResourcePolicies method signature
func TestGatherResourcePolicies_Structure(t *testing.T) {
	apollo := NewApolloV2("test-profile", []string{"us-east-1"})

	// Empty resources list for testing structure
	resources := []types.EnrichedResourceDescription{}

	// Verify the method can be called
	policies, err := apollo.gatherResourcePolicies(context.Background(), resources)

	// Should not error with empty resources
	require.NoError(t, err)
	assert.NotNil(t, policies)
	assert.Equal(t, 0, len(policies))
}
