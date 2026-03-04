package extraction

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	logstypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"golang.org/x/sync/errgroup"
)

func init() {
	mustRegister("AWS::Logs::LogGroup", "logs-events", extractLogs)
}

func extractLogs(ctx extractContext, r output.AWSResource, out *pipeline.P[output.ScanInput]) error {
	client := cloudwatchlogs.NewFromConfig(ctx.AWSConfig)
	logGroupName := r.ResourceID
	if name, ok := r.Properties["LogGroupName"].(string); ok && name != "" {
		logGroupName = name
	}

	descending := true
	streamLimit := int32(ctx.Config.MaxStreams)
	streamsResp, err := client.DescribeLogStreams(ctx.Context, &cloudwatchlogs.DescribeLogStreamsInput{LogGroupName: &logGroupName, OrderBy: logstypes.OrderByLastEventTime, Descending: &descending, Limit: &streamLimit})
	if err != nil {
		return fmt.Errorf("DescribeLogStreams failed for %s: %w", logGroupName, err)
	}

	emptyStreams := len(streamsResp.LogStreams) == 0
	if emptyStreams {
		return nil
	}

	var streamNames []string
	for _, s := range streamsResp.LogStreams {
		if s.LogStreamName != nil {
			streamNames = append(streamNames, *s.LogStreamName)
		}
	}

	missingStreamNames := len(streamNames) == 0
	if missingStreamNames {
		return nil
	}

	maxPerStream := max(1, ctx.Config.MaxEvents/len(streamNames))

	g, gctx := errgroup.WithContext(ctx.Context)
	g.SetLimit(ctx.Concurrency)

	for _, streamName := range streamNames {
		g.Go(func() error {
			return extractLogStream(gctx, client, r, out, maxPerStream, streamName, logGroupName)
		})
	}

	return g.Wait()
}

func extractLogStream(
	ctx context.Context,
	client *cloudwatchlogs.Client,
	r output.AWSResource,
	out *pipeline.P[output.ScanInput],
	maxPerStream int,
	streamName,
	logGroupName string,
) error {
	eventCount := 0
	var nextToken *string

	for eventCount < maxPerStream {
		limit := int32(maxPerStream - eventCount)
		if limit > 10000 {
			limit = 10000
		}

		eventsResp, err := client.FilterLogEvents(ctx, &cloudwatchlogs.FilterLogEventsInput{LogGroupName: &logGroupName, LogStreamNames: []string{streamName}, Limit: &limit, NextToken: nextToken})
		if err != nil {
			return fmt.Errorf("FilterLogEvents failed for %s stream %s: %w", logGroupName, streamName, err)
		}

		for _, event := range eventsResp.Events {
			if event.Message != nil && *event.Message != "" {
				label := "log-event"
				if event.EventId != nil {
					label = "log-event:" + *event.EventId
				}
				out.Send(output.ScanInputFromAWSResource(r, label, []byte(*event.Message)))
				eventCount++
			}
		}

		reachedEnd := eventsResp.NextToken == nil || len(eventsResp.Events) == 0
		if reachedEnd {
			break
		}
		nextToken = eventsResp.NextToken
	}

	return nil
}
