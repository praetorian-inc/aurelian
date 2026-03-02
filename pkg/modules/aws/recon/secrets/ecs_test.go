package secrets

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractECS_ViaDispatcher(t *testing.T) {
	cfg := ExtractorConfig{
		AWSConfigFactory: func(region string) (aws.Config, error) {
			return aws.Config{Region: region}, nil
		},
	}
	fn := ExtractContent(cfg)

	r := output.AWSResource{
		ResourceType: "AWS::ECS::TaskDefinition",
		ResourceID:   "arn:aws:ecs:us-east-1:123456789012:task-definition/my-task:1",
		Region:       "us-east-1",
		AccountRef:   "123456789012",
		Properties: map[string]any{
			"ContainerDefinitions": []any{
				map[string]any{
					"Name":  "app",
					"Image": "my-image:latest",
					"Environment": []any{
						map[string]any{"Name": "DB_PASSWORD", "Value": "supersecret123"},
					},
				},
			},
		},
	}

	out := pipeline.New[ScanInput]()
	go func() {
		defer out.Close()
		err := fn(r, out)
		require.NoError(t, err)
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Equal(t, "TaskDefinition", items[0].Label)
	assert.Contains(t, string(items[0].Content), "supersecret123")
}
