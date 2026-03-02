package secrets

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	logstypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockLogsClient struct {
	streams []logstypes.LogStream
	events  []logstypes.FilteredLogEvent
	err     error
}

func (m *mockLogsClient) DescribeLogStreams(
	ctx context.Context,
	input *cloudwatchlogs.DescribeLogStreamsInput,
	opts ...func(*cloudwatchlogs.Options),
) (*cloudwatchlogs.DescribeLogStreamsOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &cloudwatchlogs.DescribeLogStreamsOutput{
		LogStreams: m.streams,
	}, nil
}

func (m *mockLogsClient) FilterLogEvents(
	ctx context.Context,
	input *cloudwatchlogs.FilterLogEventsInput,
	opts ...func(*cloudwatchlogs.Options),
) (*cloudwatchlogs.FilterLogEventsOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &cloudwatchlogs.FilterLogEventsOutput{
		Events: m.events,
	}, nil
}

func TestExtractLogs_WithEvents(t *testing.T) {
	client := &mockLogsClient{
		streams: []logstypes.LogStream{
			{LogStreamName: aws.String("stream-1")},
		},
		events: []logstypes.FilteredLogEvent{
			{Message: aws.String("Starting app with key AKIAIOSFODNN7EXAMPLE\n")},
			{Message: aws.String("Connected to database\n")},
		},
	}

	r := output.AWSResource{
		ResourceType: "AWS::Logs::LogGroup",
		ResourceID:   "arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/my-func",
		Region:       "us-east-1",
		AccountRef:   "123456789012",
		Properties:   map[string]any{"LogGroupName": "/aws/lambda/my-func"},
	}

	out := pipeline.New[ScanInput]()
	go func() {
		defer out.Close()
		err := extractLogsWithClient(client, r, out, 10000, 10)
		require.NoError(t, err)
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Equal(t, "logs", items[0].Label)
	assert.Contains(t, string(items[0].Content), "AKIAIOSFODNN7EXAMPLE")
}

func TestExtractLogs_NoStreams(t *testing.T) {
	client := &mockLogsClient{
		streams: []logstypes.LogStream{},
	}

	r := output.AWSResource{
		ResourceType: "AWS::Logs::LogGroup",
		ResourceID:   "arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/my-func",
		Region:       "us-east-1",
		AccountRef:   "123456789012",
		Properties:   map[string]any{"LogGroupName": "/aws/lambda/my-func"},
	}

	out := pipeline.New[ScanInput]()
	go func() {
		defer out.Close()
		err := extractLogsWithClient(client, r, out, 10000, 10)
		require.NoError(t, err)
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	assert.Empty(t, items)
}
