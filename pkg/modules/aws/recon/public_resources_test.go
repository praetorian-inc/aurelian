package recon

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublicResourcesModuleMetadata(t *testing.T) {
	m := &AWSPublicResourcesModule{}

	assert.Equal(t, "public-resources", m.ID())
	assert.Equal(t, "AWS Public Resources", m.Name())
	assert.Equal(t, plugin.PlatformAWS, m.Platform())
	assert.Equal(t, plugin.CategoryRecon, m.Category())
	assert.Equal(t, "moderate", m.OpsecLevel())

	authors := m.Authors()
	require.Len(t, authors, 1)
	assert.Equal(t, "Praetorian", authors[0])

	assert.NotEmpty(t, m.Description())
	assert.NotEmpty(t, m.References())
}

func TestPublicResourcesSupportedResourceTypes(t *testing.T) {
	m := &AWSPublicResourcesModule{}
	types := m.SupportedResourceTypes()

	expected := []string{
		"AWS::EC2::Instance",
		"AWS::S3::Bucket",
		"AWS::SNS::Topic",
		"AWS::SQS::Queue",
		"AWS::Lambda::Function",
		"AWS::EFS::FileSystem",
		"AWS::Cognito::UserPool",
		"AWS::RDS::DBInstance",
	}

	assert.Equal(t, expected, types)
	assert.Len(t, types, 8)
}

func TestPublicResourcesParameters(t *testing.T) {
	m := &AWSPublicResourcesModule{}
	params, err := plugin.ParametersFrom(m.Parameters())
	require.NoError(t, err)

	paramNames := make(map[string]bool)
	for _, p := range params {
		paramNames[p.Name] = true
	}

	// Must include AWS params from AWSCommonRecon
	assert.True(t, paramNames["profile"], "should have profile param")
	assert.True(t, paramNames["regions"], "should have regions param")
	assert.True(t, paramNames["concurrency"], "should have concurrency param")

	// Must include resource-id and resource-type params
	assert.True(t, paramNames["resource-id"], "should have resource-id param")
	assert.True(t, paramNames["resource-type"], "should have resource-type param")

	// Must include org-policies param
	assert.True(t, paramNames["org-policies"], "should have org-policies param")
}
