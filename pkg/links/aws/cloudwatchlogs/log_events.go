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
	if resource.TypeName != "AWS::Logs::LogGroup" {
		slog.Debug("Skipping non-CloudWatch log group", "resource", resource.TypeName)
		return nil
	}

	config, err := cwl.GetConfigWithRuntimeArgs(resource.Region)
	if err != nil {
		slog.Error("Failed to get AWS config for region", "region", resource.Region, "error", err)
		return nil
	}

	logsClient := cloudwatchlogs.NewFromConfig(config)

	logEvents, err := cwl.fetchLogEvents(logsClient, resource.Identifier)
	if err != nil {
		slog.Error("Failed to fetch log events", "log_group", resource.Identifier, "error", err)
		return nil
	}

	if len(logEvents) == 0 {
		slog.Debug("No log events found", "log_group", resource.Identifier)
		return nil
	}

	// Concatenate all log events into a single content string
	var logContent strings.Builder
	for _, event := range logEvents {
		if event.Message != nil {
			logContent.WriteString(*event.Message)
			logContent.WriteString("\n")
		}
	}

	content := logContent.String()
	if len(content) == 0 {
		slog.Debug("No content found in log events", "log_group", resource.Identifier)
		return nil
	}

	slog.Debug("Fetched log events for scanning",
		"log_group", resource.Identifier,
		"event_count", len(logEvents),
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
