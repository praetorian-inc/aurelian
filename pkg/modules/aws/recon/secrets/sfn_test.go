package secrets

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	sfntypes "github.com/aws/aws-sdk-go-v2/service/sfn/types"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockSFNClient struct {
	executions []sfntypes.ExecutionListItem
	execDetail *sfn.DescribeExecutionOutput
	err        error
}

func (m *mockSFNClient) ListExecutions(
	ctx context.Context,
	input *sfn.ListExecutionsInput,
	opts ...func(*sfn.Options),
) (*sfn.ListExecutionsOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &sfn.ListExecutionsOutput{
		Executions: m.executions,
	}, nil
}

func (m *mockSFNClient) DescribeExecution(
	ctx context.Context,
	input *sfn.DescribeExecutionInput,
	opts ...func(*sfn.Options),
) (*sfn.DescribeExecutionOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.execDetail, nil
}

func TestExtractSFN_WithExecutions(t *testing.T) {
	client := &mockSFNClient{
		executions: []sfntypes.ExecutionListItem{
			{ExecutionArn: aws.String("arn:aws:states:us-east-1:123456789012:execution:my-sm:exec-1")},
		},
		execDetail: &sfn.DescribeExecutionOutput{
			ExecutionArn: aws.String("arn:aws:states:us-east-1:123456789012:execution:my-sm:exec-1"),
			Input:        aws.String(`{"api_key": "AKIAIOSFODNN7EXAMPLE"}`),
			Output:       aws.String(`{"result": "success"}`),
		},
	}

	r := output.AWSResource{
		ResourceType: "AWS::StepFunctions::StateMachine",
		ResourceID:   "arn:aws:states:us-east-1:123456789012:stateMachine:my-sm",
		Region:       "us-east-1",
		AccountRef:   "123456789012",
		Properties:   map[string]any{},
	}

	out := pipeline.New[ScanInput]()
	go func() {
		defer out.Close()
		err := extractSFNWithClient(client, r, out)
		require.NoError(t, err)
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Equal(t, "execution:exec-1", items[0].Label)
	assert.Contains(t, string(items[0].Content), "AKIAIOSFODNN7EXAMPLE")
}

func TestExtractSFN_NoExecutions(t *testing.T) {
	client := &mockSFNClient{
		executions: []sfntypes.ExecutionListItem{},
	}

	r := output.AWSResource{
		ResourceType: "AWS::StepFunctions::StateMachine",
		ResourceID:   "arn:aws:states:us-east-1:123456789012:stateMachine:my-sm",
		Region:       "us-east-1",
		AccountRef:   "123456789012",
		Properties:   map[string]any{},
	}

	out := pipeline.New[ScanInput]()
	go func() {
		defer out.Close()
		err := extractSFNWithClient(client, r, out)
		require.NoError(t, err)
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	assert.Empty(t, items)
}
