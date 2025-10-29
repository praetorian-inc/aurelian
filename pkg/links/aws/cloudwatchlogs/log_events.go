package cloudwatchlogs

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	jtypes "github.com/praetorian-inc/janus-framework/pkg/types"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/types"
)

const (
	// DefaultMaxEvents is the default maximum number of log events to fetch per log group
	DefaultMaxEvents = 10000
)

type AWSCloudWatchLogsEvents struct {
	*base.AwsReconLink
	maxEvents int
}

func NewAWSCloudWatchLogsEvents(configs ...cfg.Config) chain.Link {
	cwl := &AWSCloudWatchLogsEvents{
		maxEvents: DefaultMaxEvents,
	}
	cwl.AwsReconLink = base.NewAwsReconLink(cwl, configs...)
	return cwl
}

func (cwl *AWSCloudWatchLogsEvents) Process(resource *types.EnrichedResourceDescription) error {
	// Check if this is a supported CloudWatch Logs resource type
	supportedTypes := map[string]bool{
		"AWS::Logs::LogGroup":           true,
		"AWS::Logs::LogStream":          true,
		"AWS::Logs::MetricFilter":       true,
		"AWS::Logs::SubscriptionFilter": true,
	}

	if !supportedTypes[resource.TypeName] {
		slog.Debug("Skipping non-CloudWatch Logs resource", "resource", resource.TypeName)
		return nil
	}

	config, err := cwl.GetConfigWithRuntimeArgs(resource.Region)
	if err != nil {
		slog.Error("Failed to get AWS config for region", "region", resource.Region, "error", err)
		return nil
	}

	logsClient := cloudwatchlogs.NewFromConfig(config)

	var content string

	switch resource.TypeName {
	case "AWS::Logs::LogGroup":
		content, err = cwl.processLogGroup(logsClient, resource.Identifier)
	case "AWS::Logs::LogStream":
		content, err = cwl.processLogStream(logsClient, resource.Identifier)
	case "AWS::Logs::MetricFilter":
		content, err = cwl.processMetricFilter(logsClient, resource.Identifier)
	case "AWS::Logs::SubscriptionFilter":
		content, err = cwl.processSubscriptionFilter(logsClient, resource.Identifier)
	default:
		slog.Error("Unsupported resource type", "type", resource.TypeName)
		return nil
	}

	if err != nil {
		slog.Error("Failed to process resource", "resource", resource.Identifier, "type", resource.TypeName, "error", err)
		return nil
	}

	if len(content) == 0 {
		slog.Debug("No content found in resource", "resource", resource.Identifier, "type", resource.TypeName)
		return nil
	}

	slog.Debug("Processed resource for scanning",
		"resource", resource.Identifier,
		"type", resource.TypeName,
		"content_size", len(content))

	return cwl.Send(jtypes.NPInput{
		ContentBase64: base64.StdEncoding.EncodeToString([]byte(content)),
		Provenance: jtypes.NPProvenance{
			Platform:     "aws",
			ResourceType: fmt.Sprintf("%s::LogEvents", resource.TypeName),
			ResourceID:   resource.Arn.String(),
			Region:       resource.Region,
			AccountID:    resource.AccountId,
		},
	})
}

func (cwl *AWSCloudWatchLogsEvents) fetchLogEvents(client *cloudwatchlogs.Client, logGroupName string) ([]cwltypes.FilteredLogEvent, error) {
	input := &cloudwatchlogs.FilterLogEventsInput{
		LogGroupName: aws.String(logGroupName),
		Limit:        aws.Int32(10000), // Max per API call
	}

	paginator := cloudwatchlogs.NewFilterLogEventsPaginator(client, input)

	var allEvents []cwltypes.FilteredLogEvent
	eventCount := 0

	for paginator.HasMorePages() && eventCount < cwl.maxEvents {
		page, err := paginator.NextPage(cwl.Context())
		if err != nil {
			return nil, fmt.Errorf("failed to fetch log events page: %w", err)
		}

		for _, event := range page.Events {
			if eventCount >= cwl.maxEvents {
				slog.Debug("Reached max events limit", "log_group", logGroupName, "max_events", cwl.maxEvents)
				return allEvents, nil
			}
			allEvents = append(allEvents, event)
			eventCount++
		}
	}

	return allEvents, nil
}

// processLogGroup processes LogGroup resources by fetching log events
func (cwl *AWSCloudWatchLogsEvents) processLogGroup(client *cloudwatchlogs.Client, logGroupName string) (string, error) {
	logEvents, err := cwl.fetchLogEvents(client, logGroupName)
	if err != nil {
		return "", fmt.Errorf("failed to fetch log events: %w", err)
	}

	if len(logEvents) == 0 {
		return "", nil
	}

	// Concatenate all log events into a single content string
	var logContent strings.Builder
	for _, event := range logEvents {
		if event.Message != nil {
			logContent.WriteString(*event.Message)
			logContent.WriteString("\n")
		}
	}

	return logContent.String(), nil
}

// processLogStream processes LogStream resources by fetching log events from the specific stream
func (cwl *AWSCloudWatchLogsEvents) processLogStream(client *cloudwatchlogs.Client, logStreamName string) (string, error) {
	// Extract log group name from log stream name (assuming format: log-group-name/log-stream-name)
	parts := strings.Split(logStreamName, "/")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid log stream name format: %s", logStreamName)
	}
	logGroupName := strings.Join(parts[:len(parts)-1], "/")
	streamName := parts[len(parts)-1]

	// Fetch log events from the specific log stream
	input := &cloudwatchlogs.FilterLogEventsInput{
		LogGroupName:   aws.String(logGroupName),
		LogStreamNames: []string{streamName},
		Limit:          aws.Int32(10000),
	}

	paginator := cloudwatchlogs.NewFilterLogEventsPaginator(client, input)
	var allEvents []cwltypes.FilteredLogEvent
	eventCount := 0

	for paginator.HasMorePages() && eventCount < cwl.maxEvents {
		page, err := paginator.NextPage(cwl.Context())
		if err != nil {
			return "", fmt.Errorf("failed to fetch log events page: %w", err)
		}

		for _, event := range page.Events {
			if eventCount >= cwl.maxEvents {
				break
			}
			allEvents = append(allEvents, event)
			eventCount++
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

// processMetricFilter processes MetricFilter resources by extracting filter patterns and configurations
func (cwl *AWSCloudWatchLogsEvents) processMetricFilter(client *cloudwatchlogs.Client, filterName string) (string, error) {
	// Extract log group name from filter name (assuming format: log-group-name/filter-name)
	parts := strings.Split(filterName, "/")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid metric filter name format: %s", filterName)
	}
	logGroupName := strings.Join(parts[:len(parts)-1], "/")
	filterNameOnly := parts[len(parts)-1]

	// Describe the metric filter to get its configuration
	input := &cloudwatchlogs.DescribeMetricFiltersInput{
		LogGroupName:     aws.String(logGroupName),
		FilterNamePrefix: aws.String(filterNameOnly),
	}

	result, err := client.DescribeMetricFilters(cwl.Context(), input)
	if err != nil {
		return "", fmt.Errorf("failed to describe metric filter: %w", err)
	}

	if len(result.MetricFilters) == 0 {
		return "", nil
	}

	// Extract filter patterns and configurations that might contain secrets
	var content strings.Builder
	for _, filter := range result.MetricFilters {
		if filter.FilterPattern != nil {
			content.WriteString(fmt.Sprintf("Filter Pattern: %s\n", *filter.FilterPattern))
		}
		if filter.FilterName != nil {
			content.WriteString(fmt.Sprintf("Filter Name: %s\n", *filter.FilterName))
		}
		if filter.LogGroupName != nil {
			content.WriteString(fmt.Sprintf("Log Group: %s\n", *filter.LogGroupName))
		}
		// Include metric transformations which might contain sensitive data
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
	}

	return content.String(), nil
}

// processSubscriptionFilter processes SubscriptionFilter resources by extracting filter patterns and destination configurations
func (cwl *AWSCloudWatchLogsEvents) processSubscriptionFilter(client *cloudwatchlogs.Client, filterName string) (string, error) {
	// Extract log group name from filter name (assuming format: log-group-name/filter-name)
	parts := strings.Split(filterName, "/")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid subscription filter name format: %s", filterName)
	}
	logGroupName := strings.Join(parts[:len(parts)-1], "/")
	filterNameOnly := parts[len(parts)-1]

	// Describe the subscription filter to get its configuration
	input := &cloudwatchlogs.DescribeSubscriptionFiltersInput{
		LogGroupName:     aws.String(logGroupName),
		FilterNamePrefix: aws.String(filterNameOnly),
	}

	result, err := client.DescribeSubscriptionFilters(cwl.Context(), input)
	if err != nil {
		return "", fmt.Errorf("failed to describe subscription filter: %w", err)
	}

	if len(result.SubscriptionFilters) == 0 {
		return "", nil
	}

	// Extract filter patterns and destination configurations that might contain secrets
	var content strings.Builder
	for _, filter := range result.SubscriptionFilters {
		if filter.FilterPattern != nil {
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
		// Include any additional configuration that might contain secrets
		if filter.Distribution != "" {
			content.WriteString(fmt.Sprintf("Distribution: %s\n", string(filter.Distribution)))
		}
		content.WriteString("\n")
	}

	return content.String(), nil
}
