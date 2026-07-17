package recon

import (
	"encoding/json"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func imdsResource(props map[string]any) output.AWSResource {
	return output.AWSResource{
		ResourceType: "AWS::EC2::Instance",
		ResourceID:   "i-0123456789abcdef0",
		ARN:          "arn:aws:ec2:us-east-1:111122223333:instance/i-0123456789abcdef0",
		Region:       "us-east-1",
		Properties:   props,
	}
}

func TestIMDSCheck_Evaluate(t *testing.T) {
	c := imdsCheck{}
	assert.Equal(t, "AWS::EC2::Instance", c.ResourceType())

	t.Run("IMDSv1 optional -> risk", func(t *testing.T) {
		r := c.Evaluate(imdsResource(map[string]any{
			"MetadataHttpTokens":   "optional",
			"MetadataHttpEndpoint": "enabled",
			"InstanceStateName":    "running",
		}))
		require.NotNil(t, r)
		assert.Equal(t, "ec2-imdsv1-enabled", r.Name)
		assert.Equal(t, output.RiskSeverityMedium, r.Severity)
		assert.Equal(t, "arn:aws:ec2:us-east-1:111122223333:instance/i-0123456789abcdef0", r.ImpactedResourceID)
		assert.NotEmpty(t, r.Context)
	})

	t.Run("IMDSv2 required -> nil", func(t *testing.T) {
		assert.Nil(t, c.Evaluate(imdsResource(map[string]any{
			"MetadataHttpTokens": "required", "MetadataHttpEndpoint": "enabled", "InstanceStateName": "running",
		})))
	})

	t.Run("endpoint disabled -> nil", func(t *testing.T) {
		assert.Nil(t, c.Evaluate(imdsResource(map[string]any{
			"MetadataHttpTokens": "optional", "MetadataHttpEndpoint": "disabled", "InstanceStateName": "running",
		})))
	})

	t.Run("terminated -> nil", func(t *testing.T) {
		assert.Nil(t, c.Evaluate(imdsResource(map[string]any{
			"MetadataHttpTokens": "optional", "MetadataHttpEndpoint": "enabled", "InstanceStateName": "terminated",
		})))
	})

	t.Run("unenriched (no MetadataHttpTokens) -> nil", func(t *testing.T) {
		assert.Nil(t, c.Evaluate(imdsResource(map[string]any{"InstanceStateName": "running"})))
	})

	t.Run("context has only intended fields", func(t *testing.T) {
		r := c.Evaluate(imdsResource(map[string]any{
			"MetadataHttpTokens": "optional", "MetadataHttpEndpoint": "enabled",
			"MetadataHttpPutResponseHopLimit": 1, "InstanceStateName": "running",
			"IamInstanceProfile": "arn:aws:iam::111122223333:instance-profile/app",
		}))
		require.NotNil(t, r)
		var proof map[string]any
		require.NoError(t, json.Unmarshal(r.Context, &proof))
		assert.Equal(t, "optional", proof["http_tokens"])
		assert.Equal(t, "i-0123456789abcdef0", proof["instance_id"])
		assert.Equal(t, "arn:aws:iam::111122223333:instance-profile/app", proof["iam_instance_profile"])
		_, hasProps := proof["Properties"]
		assert.False(t, hasProps, "must not dump the whole AWSResource")
	})
}
