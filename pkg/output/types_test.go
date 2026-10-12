package output

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestScanInputFromAzureResource(t *testing.T) {
	t.Parallel()

	r := AzureResource{
		ResourceID:     "/subscriptions/sub-123/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1",
		ResourceType:   "Microsoft.Compute/virtualMachines",
		Location:       "eastus",
		SubscriptionID: "sub-123",
	}
	content := []byte("some secret content")
	result := ScanInputFromAzureResource(r, "UserData", content)

	assert.Equal(t, content, result.Content)
	assert.Equal(t, r.ResourceID, result.ResourceID)
	assert.Equal(t, r.ResourceType, result.ResourceType)
	assert.Equal(t, "eastus", result.Region)
	assert.Equal(t, "sub-123", result.AccountID)
	assert.Equal(t, "UserData", result.Label)
}

func TestAWSResourceAccessLevelJSONSerialization(t *testing.T) {
	t.Parallel()

	resource := AWSResource{ResourceType: "AWS::S3::Bucket", ResourceID: "x", AccountRef: "123", AccessLevel: AccessLevelPublic}
	data, err := json.Marshal(resource)
	assert.NoError(t, err)
	assert.Contains(t, string(data), `"access_level":"public"`)
}
