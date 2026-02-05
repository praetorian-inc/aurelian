package dispatcher

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

const (
	// APIMaxEventsPerPage is the AWS API maximum number of events per page
	APIMaxEventsPerPage = 10000
	// EventPreviewLength is the maximum length for event preview in logs
	EventPreviewLength = 50
)

func init() {
	// Register multiple CloudWatch Logs resource types
	RegisterAWSSecretProcessor("AWS::Logs::LogGroup", ProcessCloudWatchLogs)
	RegisterAWSSecretProcessor("AWS::Logs::LogStream", ProcessCloudWatchLogs)
	RegisterAWSSecretProcessor("AWS::Logs::MetricFilter", ProcessCloudWatchLogs)
	RegisterAWSSecretProcessor("AWS::Logs::SubscriptionFilter", ProcessCloudWatchLogs)
	RegisterAWSSecretProcessor("AWS::Logs::Destination", ProcessCloudWatchLogs)
}

// ProcessCloudWatchLogs extracts log events and configurations from CloudWatch Logs resources.
// Handles LogGroups, LogStreams, MetricFilters, SubscriptionFilters, and Destinations.
func ProcessCloudWatchLogs(
	ctx context.Context,
	resource *types.EnrichedResourceDescription,
	opts *ProcessOptions,
	resultCh chan<- types.NpInput,
) error {
	config, err := GetAWSConfigFromOptions(ctx, resource.Region, opts)
	if err != nil {
		return fmt.Errorf("failed to get AWS config for region %s: %w", resource.Region, err)
	}

	logsClient := cloudwatchlogs.NewFromConfig(config)

	var content string

	switch resource.TypeName {
	case "AWS::Logs::LogGroup":
		content, err = processLogGroup(ctx, logsClient, resource.Identifier, opts)
	case "AWS::Logs::LogStream":
		content, err = processLogStream(ctx, logsClient, resource.Identifier, opts)
	case "AWS::Logs::MetricFilter":
		content, err = processMetricFilter(ctx, logsClient, resource.Identifier)
	case "AWS::Logs::SubscriptionFilter":
		content, err = processSubscriptionFilter(ctx, logsClient, resource.Identifier)
	case "AWS::Logs::Destination":
		content, err = processDestination(ctx, logsClient, resource)
	default:
		return fmt.Errorf("unsupported CloudWatch Logs resource type: %s", resource.TypeName)
	}

	if err != nil {
		return fmt.Errorf("failed to process %s: %w", resource.TypeName, err)
	}

	if len(content) == 0 {
		// No content found - this is normal, not an error
		return nil
	}

	// Send result to channel
	// Use Content instead of ContentBase64 for text-based log events
	// NoseyParker regex patterns are designed to match plain text
	select {
	case <-ctx.Done():
		return ctx.Err()
	case resultCh <- types.NpInput{
		Content: content,
		Provenance: types.NpProvenance{
			Platform:     "aws",
			ResourceType: fmt.Sprintf("%s::LogEvents", resource.TypeName),
			ResourceID:   resource.Arn.String(),
			Region:       resource.Region,
			AccountID:    resource.AccountId,
		},
	}:
	}

	return nil
}

// processLogGroup fetches log events from multiple log streams in a log group
func processLogGroup(ctx context.Context, client *cloudwatchlogs.Client, logGroupName string, opts *ProcessOptions) (string, error) {
	maxEvents := opts.MaxEvents
	maxStreams := opts.MaxStreams

	// Get all log streams, sorted by last event time
	streamsInput := &cloudwatchlogs.DescribeLogStreamsInput{
		LogGroupName: aws.String(logGroupName),
		OrderBy:      cwltypes.OrderByLastEventTime,
		Descending:   aws.Bool(true), // Get most recently active streams first
	}

	var allStreams []cwltypes.LogStream
	streamPaginator := cloudwatchlogs.NewDescribeLogStreamsPaginator(client, streamsInput)

	for streamPaginator.HasMorePages() {
		page, err := streamPaginator.NextPage(ctx)
		if err != nil {
			// Fallback: fetch events from all streams without filtering
			logEvents, err := fetchLogEvents(ctx, client, logGroupName, opts)
			if err != nil {
				return "", fmt.Errorf("failed to fetch log events: %w", err)
			}

			if len(logEvents) == 0 {
				return "", nil
			}

			var logContent strings.Builder
			for _, event := range logEvents {
				if event.Message != nil {
					logContent.WriteString(*event.Message)
					logContent.WriteString("\n")
				}
			}
			return logContent.String(), nil
		}

		allStreams = append(allStreams, page.LogStreams...)

		// If we already have enough streams, stop paginating
		if len(allStreams) >= maxStreams {
			break
		}
	}

	if len(allStreams) == 0 {
		return "", nil
	}

	// Limit to maxStreams most recent streams
	streamsToProcess := allStreams
	if len(streamsToProcess) > maxStreams {
		streamsToProcess = streamsToProcess[:maxStreams]
	}

	// Fetch events from the selected streams
	var logContent strings.Builder
	totalEvents := 0
	eventsPerStream := maxEvents / len(streamsToProcess)
	if eventsPerStream < 100 {
		eventsPerStream = 100 // Minimum events per stream
	}

	for _, stream := range streamsToProcess {
		if stream.LogStreamName == nil {
			continue
		}

		streamName := *stream.LogStreamName

		// Calculate events limit for this stream
		remainingEvents := maxEvents - totalEvents
		streamLimit := eventsPerStream
		if streamLimit > remainingEvents {
			streamLimit = remainingEvents
		}
		if streamLimit <= 0 {
			break
		}

		// Fetch events from this specific stream
		apiLimit := int32(streamLimit)
		if apiLimit > APIMaxEventsPerPage {
			apiLimit = APIMaxEventsPerPage
		}

		filterInput := &cloudwatchlogs.FilterLogEventsInput{
			LogGroupName:   aws.String(logGroupName),
			LogStreamNames: []string{streamName},
			Limit:          aws.Int32(apiLimit),
		}

		paginator := cloudwatchlogs.NewFilterLogEventsPaginator(client, filterInput)
		streamEventCount := 0

		for paginator.HasMorePages() && streamEventCount < streamLimit {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				break // Continue with next stream
			}

			for _, event := range page.Events {
				if streamEventCount >= streamLimit {
					break
				}
				if event.Message != nil {
					logContent.WriteString(*event.Message)
					logContent.WriteString("\n")
					streamEventCount++
					totalEvents++
				}
			}

			if len(page.Events) == 0 {
				break
			}
		}

		if totalEvents >= maxEvents {
			break
		}
	}

	return logContent.String(), nil
}

// processLogStream fetches log events from a specific log stream
func processLogStream(ctx context.Context, client *cloudwatchlogs.Client, logStreamName string, opts *ProcessOptions) (string, error) {
	// Extract log group name from log stream name (format: log-group-name/log-stream-name)
	parts := strings.Split(logStreamName, "/")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid log stream name format: %s", logStreamName)
	}
	logGroupName := strings.Join(parts[:len(parts)-1], "/")
	streamName := parts[len(parts)-1]

	maxEvents := opts.MaxEvents
	apiLimit := int32(maxEvents)
	if apiLimit > APIMaxEventsPerPage {
		apiLimit = APIMaxEventsPerPage
	}

	// Fetch log events from the specific log stream
	input := &cloudwatchlogs.FilterLogEventsInput{
		LogGroupName:   aws.String(logGroupName),
		LogStreamNames: []string{streamName},
		Limit:          aws.Int32(apiLimit),
	}

	paginator := cloudwatchlogs.NewFilterLogEventsPaginator(client, input)
	var allEvents []cwltypes.FilteredLogEvent
	eventCount := 0

	for paginator.HasMorePages() && eventCount < maxEvents {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return "", fmt.Errorf("failed to fetch log events page: %w", err)
		}

		for _, event := range page.Events {
			if eventCount >= maxEvents {
				break
			}
			allEvents = append(allEvents, event)
			eventCount++
		}

		if eventCount >= maxEvents {
			break
		}
	}

	// Ensure we never return more than maxEvents
	if len(allEvents) > maxEvents {
		allEvents = allEvents[:maxEvents]
	}

	// If newest-first is enabled, reverse sort by timestamp
	if opts.NewestFirst && len(allEvents) > 0 {
		sort.Slice(allEvents, func(i, j int) bool {
			if allEvents[i].Timestamp == nil || allEvents[j].Timestamp == nil {
				return false
			}
			return *allEvents[i].Timestamp > *allEvents[j].Timestamp
		})
		if len(allEvents) > maxEvents {
			allEvents = allEvents[:maxEvents]
		}
	}

	if len(allEvents) == 0 {
		return "", nil
	}

	// Concatenate all log events into a single content string
	var logContent strings.Builder
	for _, event := range allEvents {
		if event.Message != nil {
			logContent.WriteString(*event.Message)
			logContent.WriteString("\n")
		}
	}

	return logContent.String(), nil
}

// fetchLogEvents is a helper to fetch log events from a log group
func fetchLogEvents(ctx context.Context, client *cloudwatchlogs.Client, logGroupName string, opts *ProcessOptions) ([]cwltypes.FilteredLogEvent, error) {
	maxEvents := opts.MaxEvents
	apiLimit := int32(maxEvents)
	if apiLimit > APIMaxEventsPerPage {
		apiLimit = APIMaxEventsPerPage
	}

	input := &cloudwatchlogs.FilterLogEventsInput{
		LogGroupName: aws.String(logGroupName),
		Limit:        aws.Int32(apiLimit),
	}

	paginator := cloudwatchlogs.NewFilterLogEventsPaginator(client, input)
	var allEvents []cwltypes.FilteredLogEvent
	eventCount := 0

	for paginator.HasMorePages() && eventCount < maxEvents {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch log events page: %w", err)
		}

		for _, event := range page.Events {
			if eventCount >= maxEvents {
				break
			}
			allEvents = append(allEvents, event)
			eventCount++
		}

		if eventCount >= maxEvents {
			break
		}
	}

	// Ensure we never return more than maxEvents
	if len(allEvents) > maxEvents {
		allEvents = allEvents[:maxEvents]
	}

	// If newest-first is enabled, reverse sort by timestamp
	if opts.NewestFirst && len(allEvents) > 0 {
		sort.Slice(allEvents, func(i, j int) bool {
			if allEvents[i].Timestamp == nil || allEvents[j].Timestamp == nil {
				return false
			}
			return *allEvents[i].Timestamp > *allEvents[j].Timestamp
		})
		if len(allEvents) > maxEvents {
			allEvents = allEvents[:maxEvents]
		}
	}

	return allEvents, nil
}

// processMetricFilter extracts filter patterns and configurations from metric filters
func processMetricFilter(ctx context.Context, client *cloudwatchlogs.Client, filterName string) (string, error) {
	// Extract log group name from filter name (format: log-group-name/filter-name)
	parts := strings.Split(filterName, "/")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid metric filter name format: %s", filterName)
	}
	logGroupName := strings.Join(parts[:len(parts)-1], "/")
	filterNameOnly := parts[len(parts)-1]

	input := &cloudwatchlogs.DescribeMetricFiltersInput{
		LogGroupName:     aws.String(logGroupName),
		FilterNamePrefix: aws.String(filterNameOnly),
	}

	result, err := client.DescribeMetricFilters(ctx, input)
	if err != nil {
		return "", fmt.Errorf("failed to describe metric filter: %w", err)
	}

	if len(result.MetricFilters) == 0 {
		return "", nil
	}

	// Extract filter patterns and configurations
	var content strings.Builder
	for _, filter := range result.MetricFilters {
		if filter.FilterName == nil || *filter.FilterName != filterNameOnly {
			continue
		}

		// Output raw filter pattern for secret scanning
		if filter.FilterPattern != nil {
			content.WriteString(*filter.FilterPattern)
			content.WriteString("\n")
			content.WriteString(fmt.Sprintf("Filter Pattern: %s\n", *filter.FilterPattern))
		}
		if filter.FilterName != nil {
			content.WriteString(fmt.Sprintf("Filter Name: %s\n", *filter.FilterName))
		}
		if filter.LogGroupName != nil {
			content.WriteString(fmt.Sprintf("Log Group: %s\n", *filter.LogGroupName))
		}

		// Include metric transformations
		for _, transformation := range filter.MetricTransformations {
			if transformation.MetricName != nil {
				content.WriteString(fmt.Sprintf("Metric Name: %s\n", *transformation.MetricName))
			}
			if transformation.MetricNamespace != nil {
				content.WriteString(fmt.Sprintf("Metric Namespace: %s\n", *transformation.MetricNamespace))
			}
			if transformation.MetricValue != nil {
				content.WriteString(fmt.Sprintf("Metric Value: %s\n", *transformation.MetricValue))
			}
		}
		content.WriteString("\n")
		break
	}

	return content.String(), nil
}

// processSubscriptionFilter extracts filter patterns and destination configurations
func processSubscriptionFilter(ctx context.Context, client *cloudwatchlogs.Client, filterName string) (string, error) {
	// Extract log group name from filter name (format: log-group-name/filter-name)
	parts := strings.Split(filterName, "/")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid subscription filter name format: %s", filterName)
	}
	logGroupName := strings.Join(parts[:len(parts)-1], "/")
	filterNameOnly := parts[len(parts)-1]

	input := &cloudwatchlogs.DescribeSubscriptionFiltersInput{
		LogGroupName:     aws.String(logGroupName),
		FilterNamePrefix: aws.String(filterNameOnly),
	}

	result, err := client.DescribeSubscriptionFilters(ctx, input)
	if err != nil {
		return "", fmt.Errorf("failed to describe subscription filter: %w", err)
	}

	if len(result.SubscriptionFilters) == 0 {
		return "", nil
	}

	// Extract filter patterns and destination configurations
	var content strings.Builder
	for _, filter := range result.SubscriptionFilters {
		if filter.FilterName == nil || *filter.FilterName != filterNameOnly {
			continue
		}

		// Output raw filter pattern for secret scanning
		if filter.FilterPattern != nil {
			content.WriteString(*filter.FilterPattern)
			content.WriteString("\n")
			content.WriteString(fmt.Sprintf("Filter Pattern: %s\n", *filter.FilterPattern))
		}
		if filter.FilterName != nil {
			content.WriteString(fmt.Sprintf("Filter Name: %s\n", *filter.FilterName))
		}
		if filter.LogGroupName != nil {
			content.WriteString(fmt.Sprintf("Log Group: %s\n", *filter.LogGroupName))
		}
		if filter.DestinationArn != nil {
			content.WriteString(fmt.Sprintf("Destination ARN: %s\n", *filter.DestinationArn))
		}
		if filter.RoleArn != nil {
			content.WriteString(fmt.Sprintf("Role ARN: %s\n", *filter.RoleArn))
		}
		if filter.Distribution != "" {
			content.WriteString(fmt.Sprintf("Distribution: %s\n", string(filter.Distribution)))
		}
		content.WriteString("\n")
		break
	}

	return content.String(), nil
}

// processDestination extracts destination configurations, access policies, and tags
func processDestination(ctx context.Context, client *cloudwatchlogs.Client, resource *types.EnrichedResourceDescription) (string, error) {
	destinationName := resource.Identifier

	input := &cloudwatchlogs.DescribeDestinationsInput{
		DestinationNamePrefix: aws.String(destinationName),
	}

	result, err := client.DescribeDestinations(ctx, input)
	if err != nil {
		return "", fmt.Errorf("failed to describe destination: %w", err)
	}

	if len(result.Destinations) == 0 {
		return "", nil
	}

	// Extract destination configurations
	var content strings.Builder
	for _, dest := range result.Destinations {
		if dest.DestinationName == nil || *dest.DestinationName != destinationName {
			continue
		}

		if dest.DestinationName != nil {
			content.WriteString(fmt.Sprintf("Destination Name: %s\n", *dest.DestinationName))
		}
		if dest.Arn != nil {
			content.WriteString(fmt.Sprintf("Destination ARN: %s\n", *dest.Arn))
		}
		if dest.TargetArn != nil {
			content.WriteString(fmt.Sprintf("Target ARN: %s\n", *dest.TargetArn))
		}
		if dest.RoleArn != nil {
			content.WriteString(fmt.Sprintf("Role ARN: %s\n", *dest.RoleArn))
		}
		// Access policy is a JSON string that might contain secrets
		if dest.AccessPolicy != nil && len(*dest.AccessPolicy) > 0 {
			content.WriteString(fmt.Sprintf("Access Policy: %s\n", *dest.AccessPolicy))
		}
		content.WriteString("\n")
		break
	}

	// Include tags from resource object
	tags := resource.Tags()
	if len(tags) > 0 {
		content.WriteString("Tags:\n")
		for key, value := range tags {
			content.WriteString(fmt.Sprintf("  %s: %s\n", key, value))
		}
		content.WriteString("\n")
	}

	return content.String(), nil
}
