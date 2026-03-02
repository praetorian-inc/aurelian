package secrets

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockCFNClient struct {
	templateBody string
	err          error
}

func (m *mockCFNClient) GetTemplate(
	ctx context.Context,
	input *cloudformation.GetTemplateInput,
	opts ...func(*cloudformation.Options),
) (*cloudformation.GetTemplateOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &cloudformation.GetTemplateOutput{
		TemplateBody: aws.String(m.templateBody),
	}, nil
}

func TestExtractCFN_WithTemplate(t *testing.T) {
	template := `AWSTemplateFormatVersion: "2010-09-09"
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: my-bucket
      # hardcoded key
      AccessKey: AKIAIOSFODNN7EXAMPLE`

	client := &mockCFNClient{templateBody: template}

	r := output.AWSResource{
		ResourceType: "AWS::CloudFormation::Stack",
		ResourceID:   "arn:aws:cloudformation:us-east-1:123456789012:stack/my-stack/guid",
		Region:       "us-east-1",
		AccountRef:   "123456789012",
		Properties:   map[string]any{"StackName": "my-stack"},
	}

	out := pipeline.New[ScanInput]()
	go func() {
		defer out.Close()
		err := extractCFNWithClient(client, r, out)
		require.NoError(t, err)
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Equal(t, "template.yaml", items[0].Label)
	assert.Contains(t, string(items[0].Content), "AKIAIOSFODNN7EXAMPLE")
}

func TestExtractCFN_EmptyTemplate(t *testing.T) {
	client := &mockCFNClient{templateBody: ""}

	r := output.AWSResource{
		ResourceType: "AWS::CloudFormation::Stack",
		ResourceID:   "arn:aws:cloudformation:us-east-1:123456789012:stack/my-stack/guid",
		Region:       "us-east-1",
		AccountRef:   "123456789012",
		Properties:   map[string]any{"StackName": "my-stack"},
	}

	out := pipeline.New[ScanInput]()
	go func() {
		defer out.Close()
		err := extractCFNWithClient(client, r, out)
		require.NoError(t, err)
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	assert.Empty(t, items)
}
