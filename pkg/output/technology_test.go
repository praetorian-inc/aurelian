package output_test

import (
	"encoding/json"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTechnology_JSONOmitsEmptyOptionalFields(t *testing.T) {
	b, err := json.Marshal(output.Technology{CPE: "cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"cpe":"cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*"}`, string(b))
}

func TestAWSResource_TechnologiesOmittedWhenEmpty(t *testing.T) {
	b, err := json.Marshal(output.NewAWSResource("us-east-1", "AWS::EKS::Cluster", "123456789012", "arn:x"))
	require.NoError(t, err)
	assert.NotContains(t, string(b), "technologies")
}

func TestAWSResource_TechnologiesSerialised(t *testing.T) {
	r := output.NewAWSResource("us-east-1", "AWS::EKS::Cluster", "123456789012", "arn:x")
	r.Technologies = []output.Technology{{
		CPE:      "cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*",
		Source:   "ecs-image-tag",
		Evidence: "image nginx:1.25.3-alpine",
	}}
	b, err := json.Marshal(r)
	require.NoError(t, err)
	assert.Contains(t, string(b), `"technologies":[{"cpe":"cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*","source":"ecs-image-tag","evidence":"image nginx:1.25.3-alpine"}]`)
}

func TestAzureResource_TechnologiesOmittedWhenEmpty(t *testing.T) {
	b, err := json.Marshal(output.NewAzureResource("sub", "microsoft.cache/redis", "id"))
	require.NoError(t, err)
	assert.NotContains(t, string(b), "technologies")
}

func TestGCPResource_TechnologiesOmittedWhenEmpty(t *testing.T) {
	b, err := json.Marshal(output.NewGCPResource("proj", "sqladmin.googleapis.com/Instance", "id"))
	require.NoError(t, err)
	assert.NotContains(t, string(b), "technologies")
}

func TestAzureAndGCPResource_CarryTechnologies(t *testing.T) {
	tech := output.Technology{CPE: "cpe:2.3:a:redis:redis:7.0.5:*:*:*:*:*:*:*"}

	az := output.NewAzureResource("sub", "microsoft.cache/redis", "id")
	az.Technologies = []output.Technology{tech}
	b, err := json.Marshal(az)
	require.NoError(t, err)
	assert.Contains(t, string(b), `"technologies":[{"cpe":"cpe:2.3:a:redis:redis:7.0.5:*:*:*:*:*:*:*"}]`)

	gcp := output.NewGCPResource("proj", "redis.googleapis.com/Instance", "id")
	gcp.Technologies = []output.Technology{tech}
	b, err = json.Marshal(gcp)
	require.NoError(t, err)
	assert.Contains(t, string(b), `"technologies":[{"cpe":"cpe:2.3:a:redis:redis:7.0.5:*:*:*:*:*:*:*"}]`)
}
