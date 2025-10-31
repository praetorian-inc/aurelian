package cloudwatchlogs

import (
	"fmt"
	"log/slog"
	"sort"
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
	maxEvents   int
	newestFirst bool
}

func NewAWSCloudWatchLogsEvents(configs ...cfg.Config) chain.Link {
	cwl := &AWSCloudWatchLogsEvents{
		maxEvents:   DefaultMaxEvents,
		newestFirst: false,
	}
	cwl.AwsReconLink = base.NewAwsReconLink(cwl, configs...)
	return cwl
}

func (cwl *AWSCloudWatchLogsEvents) Params() []cfg.Param {
	params := cwl.AwsReconLink.Params()
	params = append(params,
		cfg.NewParam[int]("max-events", "Maximum number of log events to fetch per log group/stream").WithDefault(DefaultMaxEvents),
		cfg.NewParam[bool]("newest-first", "Fetch newest events first instead of oldest").WithDefault(false),
	)
	return params
}

func (cwl *AWSCloudWatchLogsEvents) Initialize() error {
	if err := cwl.AwsReconLink.Initialize(); err != nil {
		return err
	}

	// Read max-events parameter
	maxEvents, err := cfg.As[int](cwl.Arg("max-events"))
	if err == nil {
		if maxEvents > 0 {
			cwl.maxEvents = maxEvents
		} else {
			slog.Warn("max-events must be positive, using default", "default", DefaultMaxEvents)
			cwl.maxEvents = DefaultMaxEvents
		}
	} else {
		cwl.maxEvents = DefaultMaxEvents
	}

	// Read newest-first parameter
	newestFirst, err := cfg.As[bool](cwl.Arg("newest-first"))
	if err == nil {
		cwl.newestFirst = newestFirst
	} else {
		cwl.newestFirst = false
	}

	slog.Debug("CloudWatch Logs Events initialized",
		"max_events", cwl.maxEvents,
		"newest_first", cwl.newestFirst)

	return nil
}

func (cwl *AWSCloudWatchLogsEvents) Process(resource *types.EnrichedResourceDescription) error {
	// Check if this is a supported CloudWatch Logs resource type
	supportedTypes := map[string]bool{
		"AWS::Logs::LogGroup":           true,
		"AWS::Logs::LogStream":          true,
		"AWS::Logs::MetricFilter":       true,
		"AWS::Logs::SubscriptionFilter": true,
		"AWS::Logs::Destination":        true,
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
	case "AWS::Logs::Destination":
		content, err = cwl.processDestination(logsClient, resource)
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

	// Use Content instead of ContentBase64 for text-based log events
	// NoseyParker regex patterns are designed to match plain text, not base64-encoded content
	return cwl.Send(jtypes.NPInput{
		// previousContentBase64: base64.StdEncoding.EncodeToString([]byte(content)),
		Content: content,
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
	// Calculate API limit (max 10k per call, but use min of maxEvents and 10k)
	apiLimit := int32(cwl.maxEvents)
	if apiLimit > 10000 {
		apiLimit = 10000
	}

	input := &cloudwatchlogs.FilterLogEventsInput{
		LogGroupName: aws.String(logGroupName),
		Limit:        aws.Int32(apiLimit),
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
				break
			}
			allEvents = append(allEvents, event)
			eventCount++
		}
		if eventCount >= cwl.maxEvents {
			break
		}
	}

	// If newest-first is enabled, reverse sort by timestamp
	if cwl.newestFirst && len(allEvents) > 0 {
		sort.Slice(allEvents, func(i, j int) bool {
			if allEvents[i].Timestamp == nil || allEvents[j].Timestamp == nil {
				return false
			}
			// Sort descending (newest first)
			return *allEvents[i].Timestamp > *allEvents[j].Timestamp
		})
		// Truncate to maxEvents after sorting (in case we fetched more than needed)
		if len(allEvents) > cwl.maxEvents {
			allEvents = allEvents[:cwl.maxEvents]
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

	// Calculate API limit (max 10k per call, but use min of maxEvents and 10k)
	apiLimit := int32(cwl.maxEvents)
	if apiLimit > 10000 {
		apiLimit = 10000
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
		if eventCount >= cwl.maxEvents {
			break
		}
	}

	// If newest-first is enabled, reverse sort by timestamp
	if cwl.newestFirst && len(allEvents) > 0 {
		sort.Slice(allEvents, func(i, j int) bool {
			if allEvents[i].Timestamp == nil || allEvents[j].Timestamp == nil {
				return false
			}
			// Sort descending (newest first)
			return *allEvents[i].Timestamp > *allEvents[j].Timestamp
		})
		// Truncate to maxEvents after sorting (in case we fetched more than needed)
		if len(allEvents) > cwl.maxEvents {
			allEvents = allEvents[:cwl.maxEvents]
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
	// Filter to exact filter name match in case prefix returned multiple results
	var content strings.Builder
	var foundFilter bool
	for _, filter := range result.MetricFilters {
		// Match exact filter name
		if filter.FilterName == nil || *filter.FilterName != filterNameOnly {
			continue
		}
		foundFilter = true

		// Output raw filter pattern prominently first (without label) so NoseyParker can detect secrets
		// The filter pattern may contain embedded secrets within quoted strings
		if filter.FilterPattern != nil {
			// Output raw pattern value on its own line for maximum visibility to secret scanners
			content.WriteString(*filter.FilterPattern)
			content.WriteString("\n")
			// Also output with label for context
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
		break // Only process the first matching filter
	}

	if !foundFilter {
		return "", nil
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
	// Filter to exact filter name match in case prefix returned multiple results
	var content strings.Builder
	var foundFilter bool
	for _, filter := range result.SubscriptionFilters {
		// Match exact filter name
		if filter.FilterName == nil || *filter.FilterName != filterNameOnly {
			continue
		}
		foundFilter = true

		// Output raw filter pattern prominently first (without label) so NoseyParker can detect secrets
		// The filter pattern may contain embedded secrets within quoted strings
		if filter.FilterPattern != nil {
			// Output raw pattern value on its own line for maximum visibility to secret scanners
			content.WriteString(*filter.FilterPattern)
			content.WriteString("\n")
			// Also output with label for context
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
		break // Only process the first matching filter
	}

	if !foundFilter {
		return "", nil
	}

	return content.String(), nil
}

// processDestination processes Destination resources by extracting destination configurations, access policies, and tags
func (cwl *AWSCloudWatchLogsEvents) processDestination(client *cloudwatchlogs.Client, resource *types.EnrichedResourceDescription) (string, error) {
	// The identifier should be the destination name
	destinationName := resource.Identifier

	// Describe the destination to get its configuration
	input := &cloudwatchlogs.DescribeDestinationsInput{
		DestinationNamePrefix: aws.String(destinationName),
	}

	result, err := client.DescribeDestinations(cwl.Context(), input)
	if err != nil {
		return "", fmt.Errorf("failed to describe destination: %w", err)
	}

	if len(result.Destinations) == 0 {
		return "", nil
	}

	// Extract destination configurations, access policies, and tags that might contain secrets
	// Filter to exact destination name match in case prefix returned multiple results
	var content strings.Builder
	var foundDestination bool
	for _, dest := range result.Destinations {
		// Match exact destination name
		if dest.DestinationName == nil || *dest.DestinationName != destinationName {
			continue
		}
		foundDestination = true

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
		break // Only process the first matching destination
	}

	if !foundDestination {
		return "", nil
	}

	// Get tags for the destination - tags can contain embedded secrets
	// Tags might already be available in the resource object, but we'll also try to fetch them via API
	tags := resource.Tags()
	if len(tags) > 0 {
		content.WriteString("Tags:\n")
		for key, value := range tags {
			content.WriteString(fmt.Sprintf("  %s: %s\n", key, value))
		}
		content.WriteString("\n")
	}

	// Also try to get tags via ListTagsLogGroup if destination name matches
	// Note: CloudWatch Logs uses ListTagsLogGroup for log groups, but for destinations,
	// tags are typically retrieved via resource tags API. However, if the destination ARN
	// is available, we can try ListTagsForResource if the API supports it.
	// For now, we'll rely on tags from the resource object which should be populated
	// from Cloud Control API or other discovery mechanisms.

	return content.String(), nil
}
