package resourcepolicies

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
)

func TestResourcePolicyCollector_SupportedResourceTypes(t *testing.T) {
	c := New(plugin.AWSCommonRecon{})
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
	collector := New(plugin.AWSCommonRecon{})
	newTypes := collector.SupportedResourceTypes()
	legacyTypes := SupportedResourceTypes()

	assert.ElementsMatch(t, legacyTypes, newTypes,
		"New collector must support the same resource types as the legacy Fetchers map")
}

func TestResourcePolicyCollector_RegistryHasAllMethods(t *testing.T) {
	c := New(plugin.AWSCommonRecon{AWSReconBase: plugin.AWSReconBase{Profile: "test-profile", ProfileDir: "/test/dir"}})
	reg := c.registry()

	for rt, method := range reg {
		assert.NotNil(t, method, "registry entry for %s should not be nil", rt)
	}
}

func TestResourcePolicyCollector_Collect_UnsupportedType(t *testing.T) {
	c := New(plugin.AWSCommonRecon{Regions: []string{"us-east-1"}})

	out := pipeline.New[output.AWSResource]()
	err := c.Collect(output.AWSResource{ResourceType: "AWS::Unsupported::Thing"}, out)
	out.Close()

	assert.NoError(t, err)

	var results []output.AWSResource
	for r := range out.Range() {
		results = append(results, r)
	}
	assert.Empty(t, results)
}
