package enumeration

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ec2Instance(id string) string {
	return ccDescription(id, fmt.Sprintf(`{"InstanceId":%q,"InstanceType":"t3.micro","UserData":"ZWNobyBoaQ=="}`, id))
}

// ec2DescribeInstances renders a DescribeInstances response. An empty launch
// time omits the launchTime element.
func ec2DescribeInstances(launchTimes map[string]string) string {
	var items strings.Builder
	for id, launch := range launchTimes {
		items.WriteString("<item><instanceId>" + id + "</instanceId>")
		if launch != "" {
			items.WriteString("<launchTime>" + launch + "</launchTime>")
		}
		items.WriteString("</item>")
	}
	return `<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><reservationSet><item><instancesSet>` +
		items.String() + `</instancesSet></item></reservationSet></DescribeInstancesResponse>`
}

func newEC2TimestampFixture(t *testing.T) (*fakeAWS, *SkipReport, *CloudControlTimestampEnumerator) {
	fake := newFakeAWS(t)
	provider := newFakeProvider(fake, "us-east-1")
	skipReport := NewSkipReport()
	return fake, skipReport, NewEC2InstanceTimestampEnumerator(newFakeCloudControl(provider, skipReport), provider, skipReport)
}

func TestEC2InstanceTimestamp_EnumerateAllStampsEachInstanceWithItsLaunchTime(t *testing.T) {
	fake, skipReport, enum := newEC2TimestampFixture(t)
	fake.reply("ListResources", ccListResources("AWS::EC2::Instance", ec2Instance("i-aaa"), ec2Instance("i-bbb"), ec2Instance("i-gone")))
	// i-gone was terminated between the CloudControl list and DescribeInstances.
	fake.reply("DescribeInstances", ec2DescribeInstances(map[string]string{
		"i-aaa": "2026-03-01T10:00:00.000Z",
		"i-bbb": "2026-07-15T08:30:00.000Z",
	}))

	resources, err := collectFakeResources(t, enum.EnumerateAll)

	require.NoError(t, err)
	got := byResourceID(resources)
	require.Len(t, got, 3, "every listed instance is emitted, including one DescribeInstances did not return")
	require.NotNil(t, got["i-aaa"].LastModified)
	require.NotNil(t, got["i-bbb"].LastModified)
	assert.Equal(t, time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC), got["i-aaa"].LastModified.UTC())
	assert.Equal(t, time.Date(2026, 7, 15, 8, 30, 0, 0, time.UTC), got["i-bbb"].LastModified.UTC())
	assert.Nil(t, got["i-gone"].LastModified, "an instance absent from DescribeInstances must stay unstamped, not guessed")
	assert.Len(t, fake.requests("DescribeInstances"), 1, "DescribeInstances is called once per region, not per instance")
	assert.Zero(t, skipReport.Len())
}

func TestEC2InstanceTimestamp_MissingLaunchTimeEmitsInstanceUnstamped(t *testing.T) {
	logs := captureLogs(t)
	fake, _, enum := newEC2TimestampFixture(t)
	fake.reply("ListResources", ccListResources("AWS::EC2::Instance", ec2Instance("i-nolaunch")))
	fake.reply("DescribeInstances", ec2DescribeInstances(map[string]string{"i-nolaunch": ""}))

	resources, err := collectFakeResources(t, enum.EnumerateAll)

	require.NoError(t, err, "a missing contracted field must not fail the region listing")
	require.Len(t, resources, 1, "the instance is still emitted")
	assert.Equal(t, "i-nolaunch", resources[0].ResourceID)
	assert.Equal(t, "AWS::EC2::Instance", resources[0].ResourceType)
	assert.Nil(t, resources[0].LastModified, "an instance without LaunchTime is unstamped so it is always scanned")

	failures := logs.timestampFailures(slog.LevelError)
	require.Len(t, failures, 1)
	assert.Equal(t, "i-nolaunch", failures[0].attrs["resource_id"])
	require.NotEmpty(t, resources[0].ARN)
	assert.Equal(t, resources[0].ARN, failures[0].attrs["arn"])
	assert.Contains(t, failures[0].attrs["error"], "LaunchTime")
}

func TestEC2InstanceTimestamp_DescribeFailureLeavesInstancesUnstamped(t *testing.T) {
	tests := []struct {
		name       string
		code       string
		wantSkip   bool
		statusCode int
	}{
		{name: "skippable error is recorded", code: "UnauthorizedOperation", wantSkip: true, statusCode: http.StatusForbidden},
		{name: "unclassified error only warns", code: "ExpiredToken", wantSkip: false, statusCode: http.StatusBadRequest},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fake, skipReport, enum := newEC2TimestampFixture(t)
			fake.reply("ListResources", ccListResources("AWS::EC2::Instance", ec2Instance("i-aaa"), ec2Instance("i-bbb")))
			fake.fail("DescribeInstances", tc.statusCode, ec2Error(tc.code))

			resources, err := collectFakeResources(t, enum.EnumerateAll)

			require.NoError(t, err, "a timestamp call failure must not fail enumeration")
			require.Len(t, resources, 2, "resources are still emitted when the timestamp call fails")
			for _, r := range resources {
				assert.Nil(t, r.LastModified, "%s must be unstamped so it is always scanned", r.ResourceID)
			}
			if tc.wantSkip {
				assertSkipRecorded(t, skipReport, "ec2", "DescribeInstances", "us-east-1", tc.code)
			} else {
				assert.Zero(t, skipReport.Len())
			}
		})
	}
}

func TestEC2InstanceTimestamp_EnumerateByARNDescribesOnlyThatInstance(t *testing.T) {
	fake, _, enum := newEC2TimestampFixture(t)
	fake.reply("GetResource", ccGetResource("AWS::EC2::Instance", ec2Instance("i-aaa")))
	fake.reply("DescribeInstances", ec2DescribeInstances(map[string]string{"i-aaa": "2026-05-05T05:05:05.000Z"}))

	resources, err := collectFakeResources(t, func(out *pipeline.P[output.AWSResource]) error {
		return enum.EnumerateByARN("arn:aws:ec2:us-east-1:123456789012:instance/i-aaa", out)
	})

	require.NoError(t, err)
	require.Len(t, resources, 1)
	require.NotNil(t, resources[0].LastModified)
	assert.Equal(t, time.Date(2026, 5, 5, 5, 5, 5, 0, time.UTC), resources[0].LastModified.UTC())

	requests := fake.requests("DescribeInstances")
	require.Len(t, requests, 1)
	form, err := url.ParseQuery(requests[0])
	require.NoError(t, err)
	assert.Equal(t, "i-aaa", form.Get("InstanceId.1"), "the by-ARN path must scope DescribeInstances to the one instance")
}
