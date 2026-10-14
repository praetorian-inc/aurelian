package output

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStructuralFactJSONSerialization(t *testing.T) {
	fact := StructuralFact{
		FactType:     "codebuild_service_role",
		ResourceARN:  "arn:aws:codebuild:us-east-1:123456789012:project/build-proj",
		ResourceType: "AWS::CodeBuild::Project",
		RoleARN:      "arn:aws:iam::123456789012:role/codebuild-service-role",
		AccountID:    "123456789012",
		Region:       "us-east-1",
	}

	data, err := json.Marshal(fact)
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	var decoded StructuralFact
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, "codebuild_service_role", decoded.FactType)
	assert.Equal(t, "arn:aws:codebuild:us-east-1:123456789012:project/build-proj", decoded.ResourceARN)
	assert.Equal(t, "AWS::CodeBuild::Project", decoded.ResourceType)
	assert.Equal(t, "arn:aws:iam::123456789012:role/codebuild-service-role", decoded.RoleARN)
	assert.Equal(t, "123456789012", decoded.AccountID)
	assert.Equal(t, "us-east-1", decoded.Region)
}

func TestStructuralFactIsAurelianModel(t *testing.T) {
	fact := StructuralFact{
		FactType:     "codebuild_service_role",
		ResourceARN:  "arn:aws:codebuild:us-east-1:123456789012:project/p",
		ResourceType: "AWS::CodeBuild::Project",
		RoleARN:      "arn:aws:iam::123456789012:role/r",
		AccountID:    "123456789012",
	}

	// StructuralFact must satisfy the AurelianModel interface so it can be
	// emitted through the pipeline alongside other output types.
	_ = fact.IsAurelianModel()
}

func TestStructuralFactOmitsEmptyRegion(t *testing.T) {
	fact := StructuralFact{
		FactType:     "codebuild_service_role",
		ResourceARN:  "arn:aws:codebuild:us-east-1:123456789012:project/p",
		ResourceType: "AWS::CodeBuild::Project",
		RoleARN:      "arn:aws:iam::123456789012:role/r",
		AccountID:    "123456789012",
	}

	data, err := json.Marshal(fact)
	require.NoError(t, err)
	assert.NotContains(t, string(data), `"region"`)
}
