package enumeration

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildECSTaskDefinitionResource_MissingRegisteredAtUsesFixedEpoch(t *testing.T) {
	td := &ecstypes.TaskDefinition{
		Family:            aws.String("legacy"),
		TaskDefinitionArn: aws.String("arn:aws:ecs:us-east-1:123456789012:task-definition/legacy:1"),
	}

	first, err := buildECSTaskDefinitionResource(td, "123456789012", "us-east-1")
	require.NoError(t, err)
	second, err := buildECSTaskDefinitionResource(td, "123456789012", "us-east-1")
	require.NoError(t, err)

	require.NotNil(t, first.LastModified, "an immutable revision must carry a fixed time, not nil")
	assert.Equal(t, time.Unix(0, 0).UTC(), *first.LastModified)
	assert.Equal(t, *first.LastModified, *second.LastModified, "the fallback never moves between runs")

	*first.LastModified = time.Now()
	third, err := buildECSTaskDefinitionResource(td, "123456789012", "us-east-1")
	require.NoError(t, err)
	assert.Equal(t, time.Unix(0, 0).UTC(), *third.LastModified, "resources must not share a mutable fallback pointer")
}
