package extraction

import (
	"strings"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func runExtractECS(t *testing.T, r output.AWSResource) []output.ScanInput {
	t.Helper()
	out := pipeline.New[output.ScanInput]()
	go func() {
		defer out.Close()
		require.NoError(t, extractECS(extractContext{}, r, out))
	}()
	items, err := out.Collect()
	require.NoError(t, err)
	return items
}

func TestExtractECS_EnvVarsEmittedAsAdjacentLines(t *testing.T) {
	r := output.AWSResource{
		ResourceType: "AWS::ECS::TaskDefinition",
		ResourceID:   "arn:aws:ecs:us-east-1:123456789012:task-definition/my-task:1",
		Region:       "us-east-1",
		AccountRef:   "123456789012",
		Properties: map[string]any{
			"Family": "my-task",
			"ContainerDefinitions": []any{
				map[string]any{
					"Name": "app",
					"Environment": []any{
						map[string]any{"Name": "AWS_ACCESS_KEY_ID", "Value": "AKIAIOSFODNN7EXAMPLE"},
						map[string]any{"Name": "AWS_SECRET_ACCESS_KEY", "Value": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
					},
				},
			},
		},
	}

	items := runExtractECS(t, r)

	var env *output.ScanInput
	for i := range items {
		if items[i].Label == "ECS Task Definition Env" {
			env = &items[i]
		}
	}
	require.NotNil(t, env, "expected an ECS Task Definition Env ScanInput")

	content := string(env.Content)
	assert.Contains(t, content, "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")
	assert.Contains(t, content, "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

	// Proximity is the whole point of the fix: the secret value must follow the
	// access-key value on the next line so the gap stays inside np.aws.6's window.
	expectedAdjacent := "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
	assert.Contains(t, content, expectedAdjacent)
	// np.aws.6 measures the gap between the END of the access key and the START of
	// the secret value; that span must be under 40 chars.
	const accessKey = "AKIAIOSFODNN7EXAMPLE"
	endOfKey := strings.Index(content, accessKey) + len(accessKey)
	gap := strings.Index(content, "wJalr") - endOfKey
	assert.Less(t, gap, 40, "access-key and secret must be within np.aws.6's 40-char window")
}

func TestExtractECS_MultipleContainersEnvConcatenated(t *testing.T) {
	r := output.AWSResource{
		ResourceType: "AWS::ECS::TaskDefinition",
		ResourceID:   "arn:aws:ecs:us-east-1:123456789012:task-definition/my-task:1",
		Properties: map[string]any{
			"ContainerDefinitions": []any{
				map[string]any{
					"Name":        "a",
					"Environment": []any{map[string]any{"Name": "FOO", "Value": "1"}},
				},
				map[string]any{
					"Name":        "b",
					"Environment": []any{map[string]any{"Name": "BAR", "Value": "2"}},
				},
				map[string]any{
					"Name": "no-env",
				},
				"not-a-map",
				map[string]any{
					"Name":        "c",
					"Environment": []any{map[string]any{"Name": "BAZ", "Value": 3}}, // non-string value skipped
				},
			},
		},
	}

	items := runExtractECS(t, r)

	var content string
	for _, it := range items {
		if it.Label == "ECS Task Definition Env" {
			content = string(it.Content)
		}
	}
	assert.Equal(t, "FOO=1\nBAR=2\n", content)
}

func TestExtractECS_NoEnvOnlyJSONScanInput(t *testing.T) {
	r := output.AWSResource{
		ResourceType: "AWS::ECS::TaskDefinition",
		ResourceID:   "arn:aws:ecs:us-east-1:123456789012:task-definition/my-task:1",
		Properties: map[string]any{
			"Family": "my-task",
			"ContainerDefinitions": []any{
				map[string]any{"Name": "app"},
			},
		},
	}

	items := runExtractECS(t, r)

	require.Len(t, items, 1)
	assert.Equal(t, "ECS Task Definition", items[0].Label)
}

func TestExtractECS_EmptyPropertiesEmitsNothing(t *testing.T) {
	items := runExtractECS(t, output.AWSResource{ResourceType: "AWS::ECS::TaskDefinition"})
	assert.Empty(t, items)
}
