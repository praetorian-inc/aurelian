package secrets

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractSSM_ViaDispatcher(t *testing.T) {
	cfg := ExtractorConfig{
		AWSConfigFactory: func(region string) (aws.Config, error) {
			return aws.Config{Region: region}, nil
		},
	}
	fn := ExtractContent(cfg)

	r := output.AWSResource{
		ResourceType: "AWS::SSM::Document",
		ResourceID:   "arn:aws:ssm:us-east-1:123456789012:document/my-doc",
		Region:       "us-east-1",
		AccountRef:   "123456789012",
		Properties: map[string]any{
			"Content": map[string]any{
				"schemaVersion": "2.2",
				"mainSteps": []any{
					map[string]any{
						"action": "aws:runShellScript",
						"inputs": map[string]any{
							"runCommand": []any{
								"export API_KEY=sk-1234567890abcdef",
							},
						},
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
	assert.Equal(t, "Document", items[0].Label)
	assert.Contains(t, string(items[0].Content), "sk-1234567890abcdef")
}
