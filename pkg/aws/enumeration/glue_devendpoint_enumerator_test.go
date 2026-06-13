package enumeration

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	gluetypes "github.com/aws/aws-sdk-go-v2/service/glue/types"
	"github.com/stretchr/testify/assert"
)

func TestBuildGlueDevEndpointResource(t *testing.T) {
	endpoint := gluetypes.DevEndpoint{
		EndpointName: aws.String("dev-ep"),
		RoleArn:      aws.String("arn:aws:iam::123456789012:role/glue-dev-role"),
	}

	r := buildGlueDevEndpointResource(endpoint, "123456789012", "us-east-2")

	assert.Equal(t, "AWS::Glue::DevEndpoint", r.ResourceType)
	assert.Equal(t, "dev-ep", r.ResourceID)
	// Glue dev endpoints carry no ARN field; the ARN is synthesized so the node keys cleanly.
	assert.Equal(t, "arn:aws:glue:us-east-2:123456789012:devEndpoint/dev-ep", r.ARN)
	assert.Equal(t, "123456789012", r.AccountRef)
	assert.Equal(t, "us-east-2", r.Region)
	// RoleArn must be captured so resource_service_role.yaml can substring-match it
	// inside the flattened properties JSON string and create the HAS_ROLE edge.
	assert.Equal(t, "arn:aws:iam::123456789012:role/glue-dev-role", r.Properties["RoleArn"])
	// Glue dev endpoints carry no resource policy.
	assert.Nil(t, r.ResourcePolicy)
}

func TestBuildGlueDevEndpointResourceNilRole(t *testing.T) {
	// A nil RoleArn must not panic and emits an empty value (fail-closed).
	endpoint := gluetypes.DevEndpoint{
		EndpointName: aws.String("no-role-ep"),
	}

	r := buildGlueDevEndpointResource(endpoint, "123456789012", "eu-west-1")

	assert.Equal(t, "arn:aws:glue:eu-west-1:123456789012:devEndpoint/no-role-ep", r.ARN)
	assert.Equal(t, "", r.Properties["RoleArn"])
}
