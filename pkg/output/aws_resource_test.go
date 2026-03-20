package output

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAWSResource_IsAdminJSONField(t *testing.T) {
	r := AWSResource{
		ResourceType: "AWS::IAM::User",
		ResourceID:   "alice",
		AccountRef:   "123456789012",
		Region:       "global",
		IsAdmin:      true,
	}

	b, err := json.Marshal(r)
	assert.NoError(t, err)
	assert.Contains(t, string(b), `"is_admin":true`)
}
