package secrets

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractContent_UnsupportedType(t *testing.T) {
	cfg := ExtractorConfig{}
	fn := ExtractContent(cfg)

	r := output.AWSResource{
		ResourceType: "AWS::S3::Bucket",
		ResourceID:   "arn:aws:s3:::my-bucket",
	}

	out := pipeline.New[ScanInput]()
	go func() {
		defer out.Close()
		err := fn(r, out)
		require.NoError(t, err)
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	assert.Empty(t, items, "unsupported type should produce no ScanInputs")
}

func TestExtractProperties(t *testing.T) {
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
						map[string]any{"Name": "API_KEY", "Value": "AKIAIOSFODNN7EXAMPLE"},
					},
				},
			},
		},
	}

	out := pipeline.New[ScanInput]()
	go func() {
		defer out.Close()
		err := extractProperties(r, out, "TaskDefinition")
		require.NoError(t, err)
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	require.Len(t, items, 1)

	assert.Equal(t, "TaskDefinition", items[0].Label)
	assert.Equal(t, r.ResourceID, items[0].ResourceID)
	assert.Equal(t, "us-east-1", items[0].Region)
	assert.Contains(t, string(items[0].Content), "AKIAIOSFODNN7EXAMPLE")
}

func TestExtractProperties_Empty(t *testing.T) {
	r := output.AWSResource{
		ResourceType: "AWS::ECS::TaskDefinition",
		ResourceID:   "arn:aws:ecs:us-east-1:123456789012:task-definition/my-task:1",
		Properties:   map[string]any{},
	}

	out := pipeline.New[ScanInput]()
	go func() {
		defer out.Close()
		err := extractProperties(r, out, "TaskDefinition")
		require.NoError(t, err)
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	assert.Empty(t, items, "empty properties should produce no ScanInputs")
}
