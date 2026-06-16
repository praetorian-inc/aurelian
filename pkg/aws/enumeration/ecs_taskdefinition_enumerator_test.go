package enumeration

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/stretchr/testify/assert"
)

func TestBuildECSTaskDefinitionResource(t *testing.T) {
	td := &ecstypes.TaskDefinition{
		Family:            aws.String("web-task"),
		TaskDefinitionArn: aws.String("arn:aws:ecs:us-east-2:123456789012:task-definition/web-task:3"),
		TaskRoleArn:       aws.String("arn:aws:iam::123456789012:role/ecs-task-role"),
		ExecutionRoleArn:  aws.String("arn:aws:iam::123456789012:role/ecs-exec-role"),
	}

	r := buildECSTaskDefinitionResource(td, "123456789012", "us-east-2")

	assert.Equal(t, "AWS::ECS::TaskDefinition", r.ResourceType)
	assert.Equal(t, "web-task", r.ResourceID)
	assert.Equal(t, "arn:aws:ecs:us-east-2:123456789012:task-definition/web-task:3", r.ARN)
	assert.Equal(t, "123456789012", r.AccountRef)
	assert.Equal(t, "us-east-2", r.Region)
	// Both TaskRoleArn and ExecutionRoleArn must be captured so resource_service_role.yaml
	// can substring-match whichever is privileged inside the flattened properties JSON string
	// and create the HAS_ROLE edge.
	assert.Equal(t, "arn:aws:iam::123456789012:role/ecs-task-role", r.Properties["TaskRoleArn"])
	assert.Equal(t, "arn:aws:iam::123456789012:role/ecs-exec-role", r.Properties["ExecutionRoleArn"])
	// Task definitions carry no resource policy.
	assert.Nil(t, r.ResourcePolicy)
}

func TestBuildECSTaskDefinitionResourceNoTaskRole(t *testing.T) {
	// A task definition with only an execution role (no task role) still emits both keys;
	// the empty TaskRoleArn is fail-closed (no ARN to match), the ExecutionRoleArn matches.
	td := &ecstypes.TaskDefinition{
		Family:            aws.String("exec-only"),
		TaskDefinitionArn: aws.String("arn:aws:ecs:us-west-2:123456789012:task-definition/exec-only:1"),
		ExecutionRoleArn:  aws.String("arn:aws:iam::123456789012:role/ecs-exec-role"),
	}

	r := buildECSTaskDefinitionResource(td, "123456789012", "us-west-2")

	assert.Equal(t, "", r.Properties["TaskRoleArn"])
	assert.Equal(t, "arn:aws:iam::123456789012:role/ecs-exec-role", r.Properties["ExecutionRoleArn"])
}

func TestBuildECSTaskDefinitionResourceNilArn(t *testing.T) {
	// A missing ARN must not panic; the ARN falls back to a synthesized form keyed on the family.
	td := &ecstypes.TaskDefinition{
		Family: aws.String("no-arn-task"),
	}

	r := buildECSTaskDefinitionResource(td, "123456789012", "eu-west-1")

	assert.Equal(t, "arn:aws:ecs:eu-west-1:123456789012:task-definition/no-arn-task", r.ARN)
	assert.Equal(t, "no-arn-task", r.ResourceID)
	assert.Equal(t, "", r.Properties["TaskRoleArn"])
	assert.Equal(t, "", r.Properties["ExecutionRoleArn"])
}
