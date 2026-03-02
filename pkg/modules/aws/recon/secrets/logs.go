package secrets

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	logstypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

// LogsClient is the subset of the CloudWatch Logs API needed by the logs extractor.
type LogsClient interface {
	DescribeLogStreams(
		ctx context.Context,
		input *cloudwatchlogs.DescribeLogStreamsInput,
		opts ...func(*cloudwatchlogs.Options),
	) (*cloudwatchlogs.DescribeLogStreamsOutput, error)
	FilterLogEvents(
		ctx context.Context,
		input *cloudwatchlogs.FilterLogEventsInput,
		opts ...func(*cloudwatchlogs.Options),
	) (*cloudwatchlogs.FilterLogEventsOutput, error)
}

// extractLogs fetches recent log events from a CloudWatch Log Group and emits
// the concatenated messages as a single ScanInput.
func extractLogs(cfg ExtractorConfig, r output.AWSResource, out *pipeline.P[ScanInput]) error {
	awsCfg, err := cfg.AWSConfigFactory(r.Region)
	if err != nil {
		return fmt.Errorf("failed to create AWS config: %w", err)
	}
	client := cloudwatchlogs.NewFromConfig(awsCfg)
	return extractLogsWithClient(client, r, out, cfg.MaxEvents, cfg.MaxStreams)
}

// extractLogsWithClient is the testable core of the logs extractor.
func extractLogsWithClient(client LogsClient, r output.AWSResource, out *pipeline.P[ScanInput], maxEvents, maxStreams int) error {
	logGroupName := r.ResourceID
	if name, ok := r.Properties["LogGroupName"].(string); ok && name != "" {
		logGroupName = name
	}

	// Get recent log streams sorted by last event time
	descending := true
	streamLimit := int32(maxStreams)
	streamsResp, err := client.DescribeLogStreams(context.Background(), &cloudwatchlogs.DescribeLogStreamsInput{
		LogGroupName: &logGroupName,
		OrderBy:      logstypes.OrderByLastEventTime,
		Descending:   &descending,
		Limit:        &streamLimit,
	})
	if err != nil {
		return fmt.Errorf("DescribeLogStreams failed for %s: %w", logGroupName, err)
	}

	if len(streamsResp.LogStreams) == 0 {
		return nil
	}

	// Collect stream names for filtering
	var streamNames []string
	for _, s := range streamsResp.LogStreams {
		if s.LogStreamName != nil {
			streamNames = append(streamNames, *s.LogStreamName)
		}
	}

	if len(streamNames) == 0 {
		return nil
	}

	// Fetch log events across all selected streams
	var messages []string
	eventCount := 0
	var nextToken *string

	for eventCount < maxEvents {
		limit := int32(maxEvents - eventCount)
		if limit > 10000 {
			limit = 10000 // AWS API maximum
		}

		input := &cloudwatchlogs.FilterLogEventsInput{
			LogGroupName:   &logGroupName,
			LogStreamNames: streamNames,
			Limit:          &limit,
			NextToken:      nextToken,
		}

		eventsResp, err := client.FilterLogEvents(context.Background(), input)
		if err != nil {
			return fmt.Errorf("FilterLogEvents failed for %s: %w", logGroupName, err)
		}

		for _, event := range eventsResp.Events {
			if event.Message != nil {
				messages = append(messages, *event.Message)
				eventCount++
			}
		}

		if eventsResp.NextToken == nil || len(eventsResp.Events) == 0 {
			break
		}
		nextToken = eventsResp.NextToken
	}

	if len(messages) == 0 {
		return nil
	}

	content := strings.Join(messages, "")
	out.Send(ScanInput{
		Content:      []byte(content),
		ResourceID:   r.ResourceID,
		ResourceType: r.ResourceType,
		Region:       r.Region,
		AccountID:    r.AccountRef,
		Label:        "logs",
	})

	return nil
}
