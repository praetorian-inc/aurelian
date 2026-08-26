package enumeration

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildECSTaskDefinitionResource(t *testing.T) {
	registered := time.Date(2026, time.August, 24, 12, 0, 0, 0, time.UTC)
	td := &ecstypes.TaskDefinition{
		Family:            aws.String("web-task"),
		TaskDefinitionArn: aws.String("arn:aws:ecs:us-east-2:123456789012:task-definition/web-task:3"),
		TaskRoleArn:       aws.String("arn:aws:iam::123456789012:role/ecs-task-role"),
		ExecutionRoleArn:  aws.String("arn:aws:iam::123456789012:role/ecs-exec-role"),
		RegisteredAt:      &registered,
		ContainerDefinitions: []ecstypes.ContainerDefinition{
			{
				Name: aws.String("app"),
				Environment: []ecstypes.KeyValuePair{
					{Name: aws.String("API_TOKEN"), Value: aws.String("secret-value")},
				},
			},
		},
	}

	r, err := buildECSTaskDefinitionResource(td, "123456789012", "us-east-2")
	require.NoError(t, err)

	assert.Equal(t, "AWS::ECS::TaskDefinition", r.ResourceType)
	assert.Equal(t, "web-task", r.ResourceID)
	assert.Equal(t, "arn:aws:ecs:us-east-2:123456789012:task-definition/web-task:3", r.ARN)
	assert.Equal(t, "123456789012", r.AccountRef)
	assert.Equal(t, "us-east-2", r.Region)
	assert.Equal(t, registered, *r.LastModified)
	// Both TaskRoleArn and ExecutionRoleArn must be captured so resource_service_role.yaml
	// can substring-match whichever is privileged inside the flattened properties JSON string
	// and create the HAS_ROLE edge.
	assert.Equal(t, "arn:aws:iam::123456789012:role/ecs-task-role", r.Properties["TaskRoleArn"])
	assert.Equal(t, "arn:aws:iam::123456789012:role/ecs-exec-role", r.Properties["ExecutionRoleArn"])

	containers, ok := r.Properties["ContainerDefinitions"].([]any)
	require.True(t, ok, "container definitions must use the CloudControl-compatible shape")
	require.Len(t, containers, 1)
	container, ok := containers[0].(map[string]any)
	require.True(t, ok)
	environment, ok := container["Environment"].([]any)
	require.True(t, ok)
	require.Len(t, environment, 1)
	assert.Equal(t, map[string]any{"Name": "API_TOKEN", "Value": "secret-value"}, environment[0])

	// Task definitions carry no resource policy.
	assert.Nil(t, r.ResourcePolicy)
}

func TestBuildECSTaskDefinitionResourceNoTaskRole(t *testing.T) {
	// A task definition with only an execution role leaves TaskRoleArn nil, so it
	// cannot match a role ARN, while the populated ExecutionRoleArn still matches.
	td := &ecstypes.TaskDefinition{
		Family:            aws.String("exec-only"),
		TaskDefinitionArn: aws.String("arn:aws:ecs:us-west-2:123456789012:task-definition/exec-only:1"),
		ExecutionRoleArn:  aws.String("arn:aws:iam::123456789012:role/ecs-exec-role"),
	}

	r, err := buildECSTaskDefinitionResource(td, "123456789012", "us-west-2")
	require.NoError(t, err)

	assert.Nil(t, r.Properties["TaskRoleArn"])
	assert.Equal(t, "arn:aws:iam::123456789012:role/ecs-exec-role", r.Properties["ExecutionRoleArn"])
}

func TestBuildECSTaskDefinitionResourceNilArn(t *testing.T) {
	// A missing ARN must not panic; the ARN falls back to a synthesized form keyed on the family.
	td := &ecstypes.TaskDefinition{
		Family: aws.String("no-arn-task"),
	}

	r, err := buildECSTaskDefinitionResource(td, "123456789012", "eu-west-1")
	require.NoError(t, err)

	assert.Equal(t, "arn:aws:ecs:eu-west-1:123456789012:task-definition/no-arn-task", r.ARN)
	assert.Equal(t, "no-arn-task", r.ResourceID)
	assert.Nil(t, r.Properties["TaskRoleArn"])
	assert.Nil(t, r.Properties["ExecutionRoleArn"])
}
