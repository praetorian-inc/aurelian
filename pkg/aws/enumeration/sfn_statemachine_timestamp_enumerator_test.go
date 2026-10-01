package enumeration

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	sfnARNPrefix = "arn:aws:states:us-east-1:123456789012:stateMachine:"
	sfnOrders    = sfnARNPrefix + "orders"
	sfnIdle      = sfnARNPrefix + "idle"
)

func sfnStateMachine(arn string) string {
	name := strings.TrimPrefix(arn, sfnARNPrefix)
	return ccDescription(arn, fmt.Sprintf(`{"Arn":%q,"StateMachineName":%q,"StateMachineType":"STANDARD"}`, arn, name))
}

func epoch(t time.Time) string {
	return fmt.Sprintf("%d", t.Unix())
}

// sfnExecution renders one execution; empty start/stop omit the field.
func sfnExecution(start, stop string) string {
	fields := []string{`"executionArn":"arn:aws:states:us-east-1:123456789012:execution:orders:run-1"`, `"name":"run-1"`, `"status":"SUCCEEDED"`, `"stateMachineArn":"` + sfnOrders + `"`}
	if start != "" {
		fields = append(fields, `"startDate":`+start)
	}
	if stop != "" {
		fields = append(fields, `"stopDate":`+stop)
	}
	return `{"executions":[{` + strings.Join(fields, ",") + `}]}`
}

const sfnNoExecutions = `{"executions":[]}`

// sfnExecutionsByMachine answers ListExecutions per state machine ARN.
func sfnExecutionsByMachine(t *testing.T, responses map[string]string) func(string) fakeAWSResponse {
	return func(body string) fakeAWSResponse {
		var input struct {
			StateMachineArn string `json:"stateMachineArn"`
		}
		require.NoError(t, json.Unmarshal([]byte(body), &input))
		resp, ok := responses[input.StateMachineArn]
		require.True(t, ok, "unexpected ListExecutions for %s", input.StateMachineArn)
		return fakeAWSResponse{status: http.StatusOK, body: resp}
	}
}

func sfnListStateMachines(creationDates map[string]string) string {
	items := make([]string, 0, len(creationDates))
	for arn, created := range creationDates {
		item := fmt.Sprintf(`{"stateMachineArn":%q,"name":%q,"type":"STANDARD"`, arn, strings.TrimPrefix(arn, sfnARNPrefix))
		if created != "" {
			item += `,"creationDate":` + created
		}
		items = append(items, item+"}")
	}
	return `{"stateMachines":[` + strings.Join(items, ",") + `]}`
}

func newSFNTimestampFixture(t *testing.T) (*fakeAWS, *SkipReport, *CloudControlTimestampEnumerator) {
	fake := newFakeAWS(t)
	provider := newFakeProvider(fake, "us-east-1")
	skipReport := NewSkipReport()
	return fake, skipReport, NewSFNStateMachineTimestampEnumerator(newFakeCloudControl(provider, skipReport), provider, skipReport)
}

func TestSFNStateMachineTimestamp_UsesLaterOfNewestExecutionStartAndStop(t *testing.T) {
	start := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	stop := time.Date(2026, 9, 1, 11, 30, 0, 0, time.UTC)
	created := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name       string
		executions string
		want       time.Time
	}{
		{name: "stopped execution uses stop time", executions: sfnExecution(epoch(start), epoch(stop)), want: stop},
		{name: "running execution uses start time", executions: sfnExecution(epoch(start), ""), want: start},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fake, _, enum := newSFNTimestampFixture(t)
			fake.reply("ListResources", ccListResources("AWS::StepFunctions::StateMachine", sfnStateMachine(sfnOrders)))
			fake.on("ListExecutions", sfnExecutionsByMachine(t, map[string]string{sfnOrders: tc.executions}))
			fake.reply("ListStateMachines", sfnListStateMachines(map[string]string{sfnOrders: epoch(created)}))

			resources, err := collectFakeResources(t, enum.EnumerateAll)

			require.NoError(t, err)
			require.Len(t, resources, 1)
			require.NotNil(t, resources[0].LastModified)
			assert.Equal(t, tc.want, resources[0].LastModified.UTC())

			requests := fake.requests("ListExecutions")
			require.Len(t, requests, 1)
			var input map[string]any
			require.NoError(t, json.Unmarshal([]byte(requests[0]), &input))
			assert.Equal(t, sfnOrders, input["stateMachineArn"], "CloudControl's identifier (the ARN) is the state machine looked up")
			assert.EqualValues(t, 1, input["maxResults"], "only the newest execution is read")
		})
	}
}

func TestSFNStateMachineTimestamp_NoExecutionsFallsBackToCreationDate(t *testing.T) {
	created := time.Date(2025, 4, 2, 3, 4, 5, 0, time.UTC)
	start := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)

	fake, _, enum := newSFNTimestampFixture(t)
	fake.reply("ListResources", ccListResources("AWS::StepFunctions::StateMachine", sfnStateMachine(sfnOrders), sfnStateMachine(sfnIdle)))
	fake.on("ListExecutions", sfnExecutionsByMachine(t, map[string]string{
		sfnOrders: sfnExecution(epoch(start), ""),
		sfnIdle:   sfnNoExecutions,
	}))
	fake.reply("ListStateMachines", sfnListStateMachines(map[string]string{sfnOrders: epoch(start), sfnIdle: epoch(created)}))

	resources, err := collectFakeResources(t, enum.EnumerateAll)

	require.NoError(t, err)
	got := byResourceID(resources)
	require.Len(t, got, 2)
	require.NotNil(t, got[sfnIdle].LastModified)
	assert.Equal(t, created, got[sfnIdle].LastModified.UTC())
	require.NotNil(t, got[sfnOrders].LastModified)
	assert.Equal(t, start, got[sfnOrders].LastModified.UTC())
}

func TestSFNStateMachineTimestamp_StateMachineCreatedAfterListIsDescribed(t *testing.T) {
	created := time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)

	fake, _, enum := newSFNTimestampFixture(t)
	fake.reply("ListResources", ccListResources("AWS::StepFunctions::StateMachine", sfnStateMachine(sfnIdle)))
	fake.on("ListExecutions", sfnExecutionsByMachine(t, map[string]string{sfnIdle: sfnNoExecutions}))
	fake.reply("ListStateMachines", sfnListStateMachines(map[string]string{}))
	fake.reply("DescribeStateMachine", fmt.Sprintf(`{"stateMachineArn":%q,"name":"idle","definition":"{}","roleArn":"arn:aws:iam::123456789012:role/r","type":"STANDARD","creationDate":%s}`, sfnIdle, epoch(created)))

	resources, err := collectFakeResources(t, enum.EnumerateAll)

	require.NoError(t, err)
	require.Len(t, resources, 1)
	require.NotNil(t, resources[0].LastModified)
	assert.Equal(t, created, resources[0].LastModified.UTC())
}

func TestSFNStateMachineTimestamp_MissingContractedFieldEmitsStateMachineUnstamped(t *testing.T) {
	start := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)

	tests := []struct {
		name          string
		executions    string
		creationDates map[string]string
		wantErrField  string
	}{
		{
			name:          "execution without StartDate",
			executions:    sfnExecution("", epoch(start)),
			creationDates: map[string]string{sfnOrders: epoch(start)},
			wantErrField:  "StartDate",
		},
		{
			name:          "listed state machine without CreationDate",
			executions:    sfnNoExecutions,
			creationDates: map[string]string{sfnOrders: ""},
			wantErrField:  "CreationDate",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logs := captureLogs(t)
			fake, _, enum := newSFNTimestampFixture(t)
			fake.reply("ListResources", ccListResources("AWS::StepFunctions::StateMachine", sfnStateMachine(sfnOrders)))
			fake.on("ListExecutions", sfnExecutionsByMachine(t, map[string]string{sfnOrders: tc.executions}))
			fake.reply("ListStateMachines", sfnListStateMachines(tc.creationDates))

			resources, err := collectFakeResources(t, enum.EnumerateAll)

			require.NoError(t, err, "a missing contracted field must not fail the region listing")
			require.Len(t, resources, 1, "the state machine is still emitted")
			assert.Equal(t, sfnOrders, resources[0].ResourceID)
			assert.Nil(t, resources[0].LastModified, "an unstampable state machine is always scanned")

			failures := logs.timestampFailures(slog.LevelError)
			require.Len(t, failures, 1)
			assert.Equal(t, sfnOrders, failures[0].attrs["resource_id"])
			assert.Contains(t, failures[0].attrs["error"], tc.wantErrField)
		})
	}
}

// One state machine in the region lacks its contracted CreationDate; only it
// loses LastModified, its neighbour is stamped, and the listing succeeds.
func TestSFNStateMachineTimestamp_MissingFieldIsIsolatedToThatResource(t *testing.T) {
	logs := captureLogs(t)
	created := time.Date(2025, 4, 2, 3, 4, 5, 0, time.UTC)
	fake, _, enum := newSFNTimestampFixture(t)
	fake.reply("ListResources", ccListResources("AWS::StepFunctions::StateMachine", sfnStateMachine(sfnOrders), sfnStateMachine(sfnIdle)))
	fake.on("ListExecutions", sfnExecutionsByMachine(t, map[string]string{sfnOrders: sfnNoExecutions, sfnIdle: sfnNoExecutions}))
	fake.reply("ListStateMachines", sfnListStateMachines(map[string]string{sfnOrders: epoch(created), sfnIdle: ""}))

	resources, err := collectFakeResources(t, enum.EnumerateAll)

	require.NoError(t, err)
	got := byResourceID(resources)
	require.Len(t, got, 2, "both state machines are emitted")
	require.Contains(t, got, sfnOrders)
	require.Contains(t, got, sfnIdle)
	require.NotNil(t, got[sfnOrders].LastModified, "the healthy neighbour keeps its timestamp")
	assert.Equal(t, created, got[sfnOrders].LastModified.UTC())
	assert.Nil(t, got[sfnIdle].LastModified, "only the resource missing CreationDate is unstamped")

	failures := logs.timestampFailures(slog.LevelError)
	require.Len(t, failures, 1, "exactly the bad resource is logged")
	require.NotEmpty(t, got[sfnIdle].ARN)
	assert.Equal(t, got[sfnIdle].ARN, failures[0].attrs["arn"])
	assert.Equal(t, sfnIdle, failures[0].attrs["resource_id"])
	assert.Equal(t, "AWS::StepFunctions::StateMachine", failures[0].attrs["resource_type"])
	assert.Equal(t, "us-east-1", failures[0].attrs["region"])
}

func TestSFNStateMachineTimestamp_ListExecutionsFailureLeavesStateMachineUnstamped(t *testing.T) {
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
			fake, skipReport, enum := newSFNTimestampFixture(t)
			fake.reply("ListResources", ccListResources("AWS::StepFunctions::StateMachine", sfnStateMachine(sfnOrders)))
			fake.fail("ListExecutions", http.StatusBadRequest, jsonError(tc.code))

			resources, err := collectFakeResources(t, enum.EnumerateAll)

			require.NoError(t, err)
			require.Len(t, resources, 1, "the state machine is still emitted")
			assert.Nil(t, resources[0].LastModified)
			if tc.wantSkip {
				assertSkipRecorded(t, skipReport, "stepfunctions", "ListExecutions", "us-east-1", tc.code)
			} else {
				assert.Zero(t, skipReport.Len())
			}
		})
	}
}

func TestSFNStateMachineTimestamp_EnumerateByARN(t *testing.T) {
	created := time.Date(2025, 4, 2, 3, 4, 5, 0, time.UTC)
	describe := func(creationDate string) string {
		body := fmt.Sprintf(`{"stateMachineArn":%q,"name":"idle","definition":"{}","roleArn":"arn:aws:iam::123456789012:role/r","type":"STANDARD"`, sfnIdle)
		if creationDate != "" {
			body += `,"creationDate":` + creationDate
		}
		return body + "}"
	}

	t.Run("no executions uses DescribeStateMachine CreationDate", func(t *testing.T) {
		fake, _, enum := newSFNTimestampFixture(t)
		fake.reply("GetResource", ccGetResource("AWS::StepFunctions::StateMachine", sfnStateMachine(sfnIdle)))
		fake.on("ListExecutions", sfnExecutionsByMachine(t, map[string]string{sfnIdle: sfnNoExecutions}))
		fake.reply("DescribeStateMachine", describe(epoch(created)))

		resources, err := collectFakeResources(t, func(out *pipeline.P[output.AWSResource]) error {
			return enum.EnumerateByARN(sfnIdle, out)
		})

		require.NoError(t, err)
		require.Len(t, resources, 1)
		require.NotNil(t, resources[0].LastModified)
		assert.Equal(t, created, resources[0].LastModified.UTC())
		assert.Empty(t, fake.requests("ListStateMachines"), "the by-ARN path describes one state machine instead of listing the region")
	})

	t.Run("DescribeStateMachine without CreationDate emits the state machine unstamped", func(t *testing.T) {
		logs := captureLogs(t)
		fake, _, enum := newSFNTimestampFixture(t)
		fake.reply("GetResource", ccGetResource("AWS::StepFunctions::StateMachine", sfnStateMachine(sfnIdle)))
		fake.on("ListExecutions", sfnExecutionsByMachine(t, map[string]string{sfnIdle: sfnNoExecutions}))
		fake.reply("DescribeStateMachine", describe(""))

		resources, err := collectFakeResources(t, func(out *pipeline.P[output.AWSResource]) error {
			return enum.EnumerateByARN(sfnIdle, out)
		})

		require.NoError(t, err)
		require.Len(t, resources, 1, "the state machine is still emitted")
		assert.Equal(t, sfnIdle, resources[0].ResourceID)
		assert.Nil(t, resources[0].LastModified)

		failures := logs.timestampFailures(slog.LevelError)
		require.Len(t, failures, 1)
		assert.Equal(t, sfnIdle, failures[0].attrs["resource_id"])
		assert.Contains(t, failures[0].attrs["error"], "CreationDate")
	})
}
