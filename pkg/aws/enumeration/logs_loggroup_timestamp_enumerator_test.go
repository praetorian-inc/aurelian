package enumeration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func logGroup(name string) string {
	return ccDescription(name, fmt.Sprintf(`{"LogGroupName":%q,"RetentionInDays":30,"Arn":"arn:aws:logs:us-east-1:123456789012:log-group:%s:*"}`, name, name))
}

// logStreams renders DescribeLogStreams; a nil entry omits lastIngestionTime.
func logStreams(ingestionMillis ...*int64) string {
	streams := make([]string, 0, len(ingestionMillis))
	for i, ms := range ingestionMillis {
		s := fmt.Sprintf(`{"logStreamName":"stream-%d","lastEventTimestamp":9999999999999`, i)
		if ms != nil {
			s += fmt.Sprintf(`,"lastIngestionTime":%d`, *ms)
		}
		streams = append(streams, s+"}")
	}
	return `{"logStreams":[` + strings.Join(streams, ",") + `]}`
}

func millis(t time.Time) *int64 {
	ms := t.UnixMilli()
	return &ms
}

func newLogGroupTimestampFixture(t *testing.T) (*fakeAWS, *SkipReport, *CloudControlTimestampEnumerator) {
	fake := newFakeAWS(t)
	provider := newFakeProvider(fake, "us-east-1")
	skipReport := NewSkipReport()
	return fake, skipReport, NewLogGroupTimestampEnumerator(newFakeCloudControl(provider, skipReport), provider, skipReport)
}

func TestLogGroupTimestamp_UsesNewestIngestionTimeAcrossSampledStreams(t *testing.T) {
	older := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	newest := time.Date(2026, 9, 1, 12, 34, 56, 789_000_000, time.UTC)
	middle := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)

	fake, _, enum := newLogGroupTimestampFixture(t)
	fake.reply("ListResources", ccListResources("AWS::Logs::LogGroup", logGroup("/app/api")))
	// The stream order is by event time, so the newest ingestion is not first.
	fake.reply("DescribeLogStreams", logStreams(millis(older), nil, millis(newest), millis(middle)))

	resources, err := collectFakeResources(t, enum.EnumerateAll)

	require.NoError(t, err)
	require.Len(t, resources, 1)
	require.NotNil(t, resources[0].LastModified)
	assert.Equal(t, newest, resources[0].LastModified.UTC(), "LastModified is the max lastIngestionTime, not lastEventTimestamp or the first stream")
}

func TestLogGroupTimestamp_SamplesTheStreamsTheExtractorReads(t *testing.T) {
	fake, _, enum := newLogGroupTimestampFixture(t)
	fake.reply("ListResources", ccListResources("AWS::Logs::LogGroup", logGroup("/app/api")))
	fake.reply("DescribeLogStreams", logStreams(millis(time.Now())))

	_, err := collectFakeResources(t, enum.EnumerateAll)
	require.NoError(t, err)

	requests := fake.requests("DescribeLogStreams")
	require.Len(t, requests, 1)
	var input map[string]any
	require.NoError(t, json.Unmarshal([]byte(requests[0]), &input))
	assert.Equal(t, "/app/api", input["logGroupName"], "the group name comes from CloudControl's LogGroupName property")
	assert.Equal(t, "LastEventTime", input["orderBy"])
	assert.Equal(t, true, input["descending"])
	assert.EqualValues(t, 10, input["limit"], "sample matches the extractor's default max-streams")
}

func TestLogGroupTimestamp_NoIngestionTimeLeavesLastModifiedNil(t *testing.T) {
	tests := map[string]string{
		"all streams lack lastIngestionTime": logStreams(nil, nil),
		"group has no streams":               logStreams(),
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			fake, _, enum := newLogGroupTimestampFixture(t)
			fake.reply("ListResources", ccListResources("AWS::Logs::LogGroup", logGroup("/app/api")))
			fake.reply("DescribeLogStreams", body)

			resources, err := collectFakeResources(t, enum.EnumerateAll)

			require.NoError(t, err, "a missing optional field is not an error")
			require.Len(t, resources, 1)
			assert.Nil(t, resources[0].LastModified)
		})
	}
}

func TestLogGroupTimestamp_DescribeFailureLeavesGroupUnstampedButEmitted(t *testing.T) {
	tests := []struct {
		name     string
		code     string
		wantSkip bool
	}{
		{name: "skippable error is recorded", code: "AccessDeniedException", wantSkip: true},
		{name: "unclassified error only warns", code: "ExpiredTokenException", wantSkip: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fake, skipReport, enum := newLogGroupTimestampFixture(t)
			fake.reply("ListResources", ccListResources("AWS::Logs::LogGroup", logGroup("/app/api")))
			fake.fail("DescribeLogStreams", http.StatusBadRequest, jsonError(tc.code))

			resources, err := collectFakeResources(t, enum.EnumerateAll)

			require.NoError(t, err)
			require.Len(t, resources, 1, "the log group is still emitted")
			assert.Nil(t, resources[0].LastModified)
			if tc.wantSkip {
				assertSkipRecorded(t, skipReport, "logs", "DescribeLogStreams", "us-east-1", tc.code)
			} else {
				assert.Zero(t, skipReport.Len())
			}
		})
	}
}

func TestLogGroupTimestamp_EnumerateByARNStampsTheGroup(t *testing.T) {
	ingested := time.Date(2026, 9, 20, 1, 2, 3, 0, time.UTC)
	fake, _, enum := newLogGroupTimestampFixture(t)
	fake.reply("GetResource", ccGetResource("AWS::Logs::LogGroup", logGroup("/app/api")))
	fake.reply("DescribeLogStreams", logStreams(millis(ingested)))

	resources, err := collectFakeResources(t, func(out *pipeline.P[output.AWSResource]) error {
		return enum.EnumerateByARN("arn:aws:logs:us-east-1:123456789012:log-group:/app/api", out)
	})

	require.NoError(t, err)
	require.Len(t, resources, 1)
	require.NotNil(t, resources[0].LastModified)
	assert.Equal(t, ingested, resources[0].LastModified.UTC())
}
