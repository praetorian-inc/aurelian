package enumeration

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	batchtypes "github.com/aws/aws-sdk-go-v2/service/batch/types"
	"github.com/stretchr/testify/assert"
)

func TestBuildJobDefinitionResource(t *testing.T) {
	jd := batchtypes.JobDefinition{
		JobDefinitionName: aws.String("etl-job"),
		JobDefinitionArn:  aws.String("arn:aws:batch:us-east-2:123456789012:job-definition/etl-job:3"),
		Status:            aws.String("ACTIVE"),
		ContainerProperties: &batchtypes.ContainerProperties{
			JobRoleArn:       aws.String("arn:aws:iam::123456789012:role/batch-job-role"),
			ExecutionRoleArn: aws.String("arn:aws:iam::123456789012:role/batch-exec-role"),
		},
	}

	r := buildJobDefinitionResource(jd, "123456789012", "us-east-2")

	assert.Equal(t, "AWS::Batch::JobDefinition", r.ResourceType)
	assert.Equal(t, "etl-job", r.ResourceID)
	assert.Equal(t, "arn:aws:batch:us-east-2:123456789012:job-definition/etl-job:3", r.ARN)
	assert.Equal(t, "123456789012", r.AccountRef)
	assert.Equal(t, "us-east-2", r.Region)
	assert.Equal(t, "ACTIVE", r.Properties["Status"])
	// Both role refs must be captured so resource_service_role.yaml can substring-match
	// whichever points at a privileged role and create the HAS_ROLE edge.
	assert.Equal(t, "arn:aws:iam::123456789012:role/batch-job-role", r.Properties["JobRoleArn"])
	assert.Equal(t, "arn:aws:iam::123456789012:role/batch-exec-role", r.Properties["ExecutionRoleArn"])
	// Job definitions carry no resource policy.
	assert.Nil(t, r.ResourcePolicy)
}

func TestBuildJobDefinitionResourceNoRole(t *testing.T) {
	// A job definition with no roles (containers run as the agent's creds) emits empty
	// role ARNs, the fail-closed case: resource_service_role.yaml will not match an
	// empty string to any role ARN, so no HAS_ROLE edge is created.
	jd := batchtypes.JobDefinition{
		JobDefinitionName:   aws.String("roleless"),
		JobDefinitionArn:    aws.String("arn:aws:batch:us-west-2:123456789012:job-definition/roleless:1"),
		ContainerProperties: &batchtypes.ContainerProperties{},
	}

	r := buildJobDefinitionResource(jd, "123456789012", "us-west-2")

	assert.Equal(t, "", r.Properties["JobRoleArn"])
	assert.Equal(t, "", r.Properties["ExecutionRoleArn"])
}

func TestBuildJobDefinitionResourceNilFields(t *testing.T) {
	// nil ContainerProperties / ARN must not panic; ARN falls back to a synthesized form.
	jd := batchtypes.JobDefinition{
		JobDefinitionName: aws.String("no-arn"),
	}

	r := buildJobDefinitionResource(jd, "123456789012", "eu-west-1")

	assert.Equal(t, "arn:aws:batch:eu-west-1:123456789012:job-definition/no-arn", r.ARN)
	assert.Equal(t, "no-arn", r.ResourceID)
	assert.Equal(t, "", r.Properties["JobRoleArn"])
	assert.Equal(t, "", r.Properties["ExecutionRoleArn"])
}
