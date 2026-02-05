package recon

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test Helpers

func createTempFile(t *testing.T, content string) string {
	t.Helper()
	tmpFile, err := os.CreateTemp("", "apollo-test-*.json")
	require.NoError(t, err)

	_, err = tmpFile.WriteString(content)
	require.NoError(t, err)

	err = tmpFile.Close()
	require.NoError(t, err)

	return tmpFile.Name()
}

// 1. Constructor and Builder Pattern Tests

func TestNewApolloOfflineV2(t *testing.T) {
	gaadPath := "/path/to/gaad.json"

	apollo := NewApolloOfflineV2(gaadPath)

	require.NotNil(t, apollo)
	assert.Equal(t, gaadPath, apollo.GaadFile)
	assert.Empty(t, apollo.OrgPolicyFile, "OrgPolicyFile should be empty by default")
	assert.Empty(t, apollo.ResourcePoliciesFile, "ResourcePoliciesFile should be empty by default")
}

func TestApolloOfflineV2_WithOrgPolicyFile(t *testing.T) {
	apollo := NewApolloOfflineV2("/gaad.json")

	result := apollo.WithOrgPolicyFile("/path/to/policies.json")

	assert.Equal(t, "/path/to/policies.json", apollo.OrgPolicyFile)
	assert.Equal(t, apollo, result, "Should return self for method chaining")
}

func TestApolloOfflineV2_WithResourcePoliciesFile(t *testing.T) {
	apollo := NewApolloOfflineV2("/gaad.json")

	result := apollo.WithResourcePoliciesFile("/path/to/resource-policies.json")

	assert.Equal(t, "/path/to/resource-policies.json", apollo.ResourcePoliciesFile)
	assert.Equal(t, apollo, result, "Should return self for method chaining")
}

func TestApolloOfflineV2_BuilderChaining(t *testing.T) {
	apollo := NewApolloOfflineV2("/gaad.json").
		WithOrgPolicyFile("/org.json").
		WithResourcePoliciesFile("/resources.json")

	assert.Equal(t, "/gaad.json", apollo.GaadFile)
	assert.Equal(t, "/org.json", apollo.OrgPolicyFile)
	assert.Equal(t, "/resources.json", apollo.ResourcePoliciesFile)
}

// 2. loadGaad Tests

func TestLoadGaad_ValidObjectFormat(t *testing.T) {
	// Create temp file with valid GAAD object
	gaadJSON := `{
        "UserDetailList": [{"UserName": "test-user"}],
        "GroupDetailList": [],
        "RoleDetailList": [],
        "Policies": []
    }`
	tmpFile := createTempFile(t, gaadJSON)
	defer os.Remove(tmpFile)

	apollo := NewApolloOfflineV2(tmpFile)
	gaad, err := apollo.loadGaad()

	require.NoError(t, err)
	require.NotNil(t, gaad)
	assert.Len(t, gaad.UserDetailList, 1)
}

func TestLoadGaad_ValidArrayFormat(t *testing.T) {
	gaadJSON := `[{
        "UserDetailList": [{"UserName": "array-user"}],
        "GroupDetailList": [],
        "RoleDetailList": [],
        "Policies": []
    }]`
	tmpFile := createTempFile(t, gaadJSON)
	defer os.Remove(tmpFile)

	apollo := NewApolloOfflineV2(tmpFile)
	gaad, err := apollo.loadGaad()

	require.NoError(t, err)
	require.NotNil(t, gaad)
	assert.Len(t, gaad.UserDetailList, 1)
}

func TestLoadGaad_EmptyGaadFile(t *testing.T) {
	apollo := NewApolloOfflineV2("")

	_, err := apollo.loadGaad()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "gaad-file is required")
}

func TestLoadGaad_MissingFile(t *testing.T) {
	apollo := NewApolloOfflineV2("/nonexistent/path/gaad.json")

	_, err := apollo.loadGaad()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read GAAD file")
}

func TestLoadGaad_EmptyArray(t *testing.T) {
	tmpFile := createTempFile(t, "[]")
	defer os.Remove(tmpFile)

	apollo := NewApolloOfflineV2(tmpFile)
	_, err := apollo.loadGaad()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty array")
}

func TestLoadGaad_InvalidJSON(t *testing.T) {
	tmpFile := createTempFile(t, "not valid json {")
	defer os.Remove(tmpFile)

	apollo := NewApolloOfflineV2(tmpFile)
	_, err := apollo.loadGaad()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unmarshal")
}

// 3. loadOrgPolicies Tests

func TestLoadOrgPolicies_NoFileProvided(t *testing.T) {
	apollo := NewApolloOfflineV2("/gaad.json")
	// OrgPolicyFile is empty by default

	policies, err := apollo.loadOrgPolicies()

	require.NoError(t, err)
	require.NotNil(t, policies)
	// Should be equivalent to NewDefaultOrgPolicies()
}

func TestLoadOrgPolicies_ValidObjectFormat(t *testing.T) {
	orgJSON := `{
        "Policies": [{"PolicyName": "test-policy"}]
    }`
	tmpFile := createTempFile(t, orgJSON)
	defer os.Remove(tmpFile)

	apollo := NewApolloOfflineV2("/gaad.json").WithOrgPolicyFile(tmpFile)
	policies, err := apollo.loadOrgPolicies()

	require.NoError(t, err)
	require.NotNil(t, policies)
}

func TestLoadOrgPolicies_ValidArrayFormat(t *testing.T) {
	orgJSON := `[{
        "Policies": [{"PolicyName": "array-policy"}]
    }]`
	tmpFile := createTempFile(t, orgJSON)
	defer os.Remove(tmpFile)

	apollo := NewApolloOfflineV2("/gaad.json").WithOrgPolicyFile(tmpFile)
	policies, err := apollo.loadOrgPolicies()

	require.NoError(t, err)
	require.NotNil(t, policies)
}

func TestLoadOrgPolicies_EmptyArrayReturnsDefault(t *testing.T) {
	tmpFile := createTempFile(t, "[]")
	defer os.Remove(tmpFile)

	apollo := NewApolloOfflineV2("/gaad.json").WithOrgPolicyFile(tmpFile)
	policies, err := apollo.loadOrgPolicies()

	require.NoError(t, err)
	require.NotNil(t, policies, "Should return default policies for empty array")
}

func TestLoadOrgPolicies_MissingFile(t *testing.T) {
	apollo := NewApolloOfflineV2("/gaad.json").
		WithOrgPolicyFile("/nonexistent/org-policies.json")

	_, err := apollo.loadOrgPolicies()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read org policies file")
}

// 4. loadResourcePolicies Tests

func TestLoadResourcePolicies_NoFileProvided(t *testing.T) {
	apollo := NewApolloOfflineV2("/gaad.json")
	// ResourcePoliciesFile is empty by default

	policies, err := apollo.loadResourcePolicies()

	require.NoError(t, err)
	require.NotNil(t, policies)
	assert.Len(t, policies, 0)
}

func TestLoadResourcePolicies_ValidObjectFormat(t *testing.T) {
	policiesJSON := `{
        "arn:aws:s3:::bucket": {"Version": "2012-10-17", "Statement": []}
    }`
	tmpFile := createTempFile(t, policiesJSON)
	defer os.Remove(tmpFile)

	apollo := NewApolloOfflineV2("/gaad.json").WithResourcePoliciesFile(tmpFile)
	policies, err := apollo.loadResourcePolicies()

	require.NoError(t, err)
	require.NotNil(t, policies)
	assert.Len(t, policies, 1)
	assert.Contains(t, policies, "arn:aws:s3:::bucket")
}

func TestLoadResourcePolicies_ValidArrayFormat(t *testing.T) {
	policiesJSON := `[{
        "arn:aws:s3:::bucket": {"Version": "2012-10-17", "Statement": []}
    }]`
	tmpFile := createTempFile(t, policiesJSON)
	defer os.Remove(tmpFile)

	apollo := NewApolloOfflineV2("/gaad.json").WithResourcePoliciesFile(tmpFile)
	policies, err := apollo.loadResourcePolicies()

	require.NoError(t, err)
	require.NotNil(t, policies)
	assert.Len(t, policies, 1)
}

func TestLoadResourcePolicies_EmptyArrayReturnsEmptyMap(t *testing.T) {
	tmpFile := createTempFile(t, "[]")
	defer os.Remove(tmpFile)

	apollo := NewApolloOfflineV2("/gaad.json").WithResourcePoliciesFile(tmpFile)
	policies, err := apollo.loadResourcePolicies()

	require.NoError(t, err)
	require.NotNil(t, policies)
	assert.Len(t, policies, 0)
}

func TestLoadResourcePolicies_MissingFile(t *testing.T) {
	apollo := NewApolloOfflineV2("/gaad.json").
		WithResourcePoliciesFile("/nonexistent/resource-policies.json")

	_, err := apollo.loadResourcePolicies()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read resource policies file")
}

// 5. Run Method Tests

func TestRun_MissingGaadFileReturnsError(t *testing.T) {
	apollo := NewApolloOfflineV2("")

	_, err := apollo.Run(context.Background())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load GAAD")
}

func TestRun_OptionalFilesMissingSucceeds(t *testing.T) {
	// Create minimal valid GAAD file
	gaadJSON := `{
        "UserDetailList": [],
        "GroupDetailList": [],
        "RoleDetailList": [],
        "Policies": []
    }`
	tmpFile := createTempFile(t, gaadJSON)
	defer os.Remove(tmpFile)

	apollo := NewApolloOfflineV2(tmpFile)
	// No OrgPolicyFile or ResourcePoliciesFile set

	result, err := apollo.Run(context.Background())

	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestRun_WithAllFilesSucceeds(t *testing.T) {
	gaadJSON := `{
        "UserDetailList": [{"UserName": "test-user", "Path": "/", "UserId": "123", "Arn": "arn:aws:iam::123:user/test"}],
        "GroupDetailList": [],
        "RoleDetailList": [],
        "Policies": []
    }`
	gaadFile := createTempFile(t, gaadJSON)
	defer os.Remove(gaadFile)

	orgJSON := `{"Policies": []}`
	orgFile := createTempFile(t, orgJSON)
	defer os.Remove(orgFile)

	resourceJSON := `{}`
	resourceFile := createTempFile(t, resourceJSON)
	defer os.Remove(resourceFile)

	apollo := NewApolloOfflineV2(gaadFile).
		WithOrgPolicyFile(orgFile).
		WithResourcePoliciesFile(resourceFile)

	result, err := apollo.Run(context.Background())

	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestRun_InvalidGaadFileReturnsError(t *testing.T) {
	tmpFile := createTempFile(t, "invalid json")
	defer os.Remove(tmpFile)

	apollo := NewApolloOfflineV2(tmpFile)
	_, err := apollo.Run(context.Background())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load GAAD")
}
