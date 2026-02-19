package resourcepolicies

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/stretchr/testify/assert"
)

func TestResourcePolicyCollector_SupportedResourceTypes(t *testing.T) {
	c := New("", "")
	types := c.SupportedResourceTypes()

	assert.Len(t, types, 7)

	expected := []string{
		"AWS::S3::Bucket",
		"AWS::Lambda::Function",
		"AWS::SNS::Topic",
		"AWS::SQS::Queue",
		"AWS::EFS::FileSystem",
		"AWS::OpenSearchService::Domain",
		"AWS::Elasticsearch::Domain",
	}
	for _, e := range expected {
		assert.Contains(t, types, e)
	}
}

func TestResourcePolicyCollector_SupportedResourceTypes_MatchesLegacy(t *testing.T) {
	collector := New("", "")
	newTypes := collector.SupportedResourceTypes()
	legacyTypes := SupportedResourceTypes()

	assert.ElementsMatch(t, legacyTypes, newTypes,
		"New collector must support the same resource types as the legacy Fetchers map")
}

func TestResourcePolicyCollector_RegistryHasAllMethods(t *testing.T) {
	c := New("test-profile", "/test/dir")
	reg := c.registry()

	// Every entry in the registry should be a non-nil function
	for rt, method := range reg {
		assert.NotNil(t, method, "registry entry for %s should not be nil", rt)
	}
}

func TestResourcePolicyCollector_Collect_EmptyInput(t *testing.T) {
	c := New("", "")

	results, err := c.Collect(map[string][]output.AWSResource{})
	assert.NoError(t, err)
	assert.Empty(t, results)
}

func TestResourcePolicyCollector_Collect_NilRegionSkipped(t *testing.T) {
	c := New("", "")

	resources := map[string][]output.AWSResource{
		"us-east-1": {},
	}

	results, err := c.Collect(resources)
	assert.NoError(t, err)
	assert.Empty(t, results)
}
