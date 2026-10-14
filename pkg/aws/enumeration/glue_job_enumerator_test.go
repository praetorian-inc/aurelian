package enumeration

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	gluetypes "github.com/aws/aws-sdk-go-v2/service/glue/types"
	"github.com/stretchr/testify/assert"
)

func TestBuildGlueJobResource(t *testing.T) {
	job := gluetypes.Job{
		Name: aws.String("etl-job"),
		Role: aws.String("arn:aws:iam::123456789012:role/glue-job-role"),
	}

	r := buildGlueJobResource(job, "123456789012", "us-east-2")

	assert.Equal(t, "AWS::Glue::Job", r.ResourceType)
	assert.Equal(t, "etl-job", r.ResourceID)
	// Glue jobs carry no ARN field; the ARN is synthesized so the node keys cleanly.
	assert.Equal(t, "arn:aws:glue:us-east-2:123456789012:job/etl-job", r.ARN)
	assert.Equal(t, "123456789012", r.AccountRef)
	assert.Equal(t, "us-east-2", r.Region)
	// Role (when given as an ARN) must be captured so resource_service_role.yaml can
	// substring-match it inside the flattened properties JSON string and create the HAS_ROLE edge.
	assert.Equal(t, "arn:aws:iam::123456789012:role/glue-job-role", r.Properties["Role"])
	// Glue jobs carry no resource policy.
	assert.Nil(t, r.ResourcePolicy)
}

func TestBuildGlueJobResourceRoleName(t *testing.T) {
	// A role given as a NAME (not an ARN) is captured verbatim but will NOT substring-match
	// any role ARN — fail-closed, consistent with resource_service_role.yaml.
	job := gluetypes.Job{
		Name: aws.String("name-role-job"),
		Role: aws.String("glue-job-role"),
	}

	r := buildGlueJobResource(job, "123456789012", "us-west-2")

	assert.Equal(t, "glue-job-role", r.Properties["Role"])
}

func TestBuildGlueJobResourceNilRole(t *testing.T) {
	// A nil Role must not panic and emits an empty value.
	job := gluetypes.Job{
		Name: aws.String("no-role-job"),
	}

	r := buildGlueJobResource(job, "123456789012", "eu-west-1")

	assert.Equal(t, "arn:aws:glue:eu-west-1:123456789012:job/no-role-job", r.ARN)
	assert.Equal(t, "", r.Properties["Role"])
}
