package recon

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/aws/resourcetypes"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Module metadata tests ---

func TestAWSListAllResources_ID(t *testing.T) {
	m := &AWSListAllResourcesModule{}
	assert.Equal(t, "list-all", m.ID())
}

func TestAWSListAllResources_Platform(t *testing.T) {
	m := &AWSListAllResourcesModule{}
	assert.Equal(t, plugin.PlatformAWS, m.Platform())
}

func TestAWSListAllResources_ConcurrencyParameter(t *testing.T) {
	m := &AWSListAllResourcesModule{}
	params := m.Parameters()

	var concurrencyParam *plugin.Parameter
	for i := range params {
		if params[i].Name == "concurrency" {
			concurrencyParam = &params[i]
			break
		}
	}

	require.NotNil(t, concurrencyParam, "concurrency parameter must exist")
	assert.Equal(t, "int", concurrencyParam.Type)
	assert.Equal(t, 5, concurrencyParam.Default)
	assert.False(t, concurrencyParam.Required)
}

// --- Resource type list tests ---

func TestGetKeySummaryResourceTypes(t *testing.T) {
	types := resourcetypes.GetSummary()
	assert.Contains(t, types, "AWS::EC2::Instance")
	assert.Contains(t, types, "AWS::S3::Bucket")
	assert.Contains(t, types, "AWS::Lambda::Function")
	assert.Less(t, len(types), len(resourcetypes.GetAll()))
}

func TestGetAllResourceTypes(t *testing.T) {
	types := resourcetypes.GetAll()
	assert.Greater(t, len(types), 10, "should have comprehensive resource type list")
	summary := resourcetypes.GetSummary()
	for _, s := range summary {
		assert.Contains(t, types, s, "full list should include all summary types")
	}
}
