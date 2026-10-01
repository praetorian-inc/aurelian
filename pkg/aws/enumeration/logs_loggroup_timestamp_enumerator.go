package enumeration

import (
	"context"
	"log/slog"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	logstypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/praetorian-inc/aurelian/pkg/output"
)

// logGroupStreamSample matches the extractor's default max-streams: the
// extractor only reads the streams with the newest events, so those are the
// streams whose ingestion can change what it scans.
const logGroupStreamSample = 10

// logGroupLastModified stamps log groups with the newest LastIngestionTime of
// their most recently written streams. Ingestion time, unlike event
// timestamps, is set by CloudWatch and cannot be backdated by the writer.
type logGroupLastModified struct {
	provider   *AWSConfigProvider
	skipReport *SkipReport
}

func NewLogGroupTimestampEnumerator(cc *CloudControlEnumerator, provider *AWSConfigProvider, skipReport *SkipReport) *CloudControlTimestampEnumerator {
	return newCloudControlTimestampEnumerator(cc, "AWS::Logs::LogGroup", &logGroupLastModified{provider: provider, skipReport: skipReport})
}

func (s *logGroupLastModified) regionStamper(region string) stampFunc {
	return s.resourceStamper(region)
}

func (s *logGroupLastModified) resourceStamper(region string) stampFunc {
	return func(r *output.AWSResource) error {
		r.LastModified = s.lastIngestion(region, r)
		return nil
	}
}

func (s *logGroupLastModified) lastIngestion(region string, r *output.AWSResource) *time.Time {
	name := logGroupName(r)
	cfg, err := s.provider.GetAWSConfig(region)
	if err != nil {
		logTimestampFailure(slog.LevelWarn, err, "logs", "DescribeLogStreams", region, r)
		return nil
	}

	resp, err := cloudwatchlogs.NewFromConfig(*cfg).DescribeLogStreams(context.Background(), &cloudwatchlogs.DescribeLogStreamsInput{
		LogGroupName: aws.String(name),
		OrderBy:      logstypes.OrderByLastEventTime,
		Descending:   aws.Bool(true),
		Limit:        aws.Int32(logGroupStreamSample),
	})
	if err != nil {
		if op := ClassifySkippable(err, "logs", "DescribeLogStreams", region); op != nil {
			s.skipReport.Record(*op)
			return nil
		}
		logTimestampFailure(slog.LevelWarn, err, "logs", "DescribeLogStreams", region, r)
		return nil
	}

	var newest *int64
	for _, stream := range resp.LogStreams {
		if stream.LastIngestionTime != nil && (newest == nil || *stream.LastIngestionTime > *newest) {
			newest = stream.LastIngestionTime
		}
	}
	if newest == nil {
		return nil
	}
	t := time.UnixMilli(*newest).UTC()
	return &t
}

func logGroupName(r *output.AWSResource) string {
	if name, ok := r.Properties["LogGroupName"].(string); ok && name != "" {
		return name
	}
	return r.ResourceID
}
