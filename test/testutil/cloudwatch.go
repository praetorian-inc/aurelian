//go:build integration

package testutil

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	logstypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
)

// EnsureLogEvent checks whether the given CloudWatch log stream has any recent
// events. If not, it writes message as a new log event. This is useful for
// fixtures with short retention periods where events may have expired between
// runs.
func EnsureLogEvent(t *testing.T, region, logGroupName, logStreamName, message string) {
	t.Helper()

	ctx := context.Background()
	client, err := newCloudWatchLogsClient(ctx, region)
	if err != nil {
		t.Fatalf("create CloudWatch Logs client: %v", err)
	}

	if hasRecentEvents(ctx, client, logGroupName, logStreamName) {
		t.Logf("log stream %s/%s already has events, skipping write", logGroupName, logStreamName)
		return
	}

	t.Logf("no recent events in %s/%s, writing log event", logGroupName, logStreamName)

	_, err = client.PutLogEvents(ctx, &cloudwatchlogs.PutLogEventsInput{
		LogGroupName:  &logGroupName,
		LogStreamName: &logStreamName,
		LogEvents: []logstypes.InputLogEvent{
			{
				Timestamp: aws.Int64(time.Now().UnixMilli()),
				Message:   &message,
			},
		},
	})
	if err != nil {
		t.Fatalf("PutLogEvents to %s/%s: %v", logGroupName, logStreamName, err)
	}
}

func hasRecentEvents(ctx context.Context, client *cloudwatchlogs.Client, logGroupName, logStreamName string) bool {
	limit := int32(1)
	resp, err := client.FilterLogEvents(ctx, &cloudwatchlogs.FilterLogEventsInput{
		LogGroupName:   &logGroupName,
		LogStreamNames: []string{logStreamName},
		Limit:          &limit,
	})
	if err != nil {
		return false
	}
	return len(resp.Events) > 0
}

func newCloudWatchLogsClient(ctx context.Context, region string) (*cloudwatchlogs.Client, error) {
	opts := []func(*config.LoadOptions) error{config.WithRegion(region)}
	if profile := os.Getenv("AWS_PROFILE"); profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(profile))
	}

	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}

	return cloudwatchlogs.NewFromConfig(cfg), nil
}
