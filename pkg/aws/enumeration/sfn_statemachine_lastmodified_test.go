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

func sfnName(arn string) string {
	return strings.TrimPrefix(arn, sfnARNPrefix)
}

func epoch(t time.Time) string {
	return fmt.Sprintf("%d", t.Unix())
}

// sfnListStateMachines renders the ListStateMachines summaries the native
// enumerator pages through; it reads only StateMachineArn from each.
func sfnListStateMachines(arns ...string) string {
	items := make([]string, 0, len(arns))
	for _, arn := range arns {
		items = append(items, fmt.Sprintf(`{"stateMachineArn":%q,"name":%q,"type":"STANDARD"}`, arn, sfnName(arn)))
	}
	return `{"stateMachines":[` + strings.Join(items, ",") + `]}`
}

// sfnDescribe renders DescribeStateMachine output; an empty creationDate omits
// the field.
func sfnDescribe(arn, creationDate string) string {
	body := fmt.Sprintf(`{"stateMachineArn":%q,"name":%q,"definition":"{}","roleArn":"arn:aws:iam::123456789012:role/r","type":"STANDARD"`, arn, sfnName(arn))
	if creationDate != "" {
		body += `,"creationDate":` + creationDate
	}
	return body + "}"
}

// sfnDescribeByMachine answers DescribeStateMachine per state machine ARN, so a
// region can mix machines with and without a contracted CreationDate.
func sfnDescribeByMachine(t *testing.T, creationDates map[string]string) func(string) fakeAWSResponse {
	return func(body string) fakeAWSResponse {
		arn, ok := sfnRequestARN(t, "DescribeStateMachine", body)
		if !ok {
			return sfnUnexpected()
		}
		created, found := creationDates[arn]
		if !found {
			assert.Fail(t, "unexpected DescribeStateMachine", "state machine %q", arn)
			return sfnUnexpected()
		}
		return fakeAWSResponse{status: http.StatusOK, body: sfnDescribe(arn, created)}
	}
}

// sfnExecution renders one execution; an empty start or stop omits that field.
func sfnExecution(start, stop string) string {
	return sfnRedrivenExecution(start, stop, "")
}

// sfnRedrivenExecution renders one execution carrying a redriveDate, the key
// AWS sorts a redriven running execution by. An empty field is omitted.
func sfnRedrivenExecution(start, stop, redrive string) string {
	fields := []string{
		`"executionArn":"arn:aws:states:us-east-1:123456789012:execution:orders:run-1"`,
		`"name":"run-1"`, `"status":"SUCCEEDED"`, `"stateMachineArn":"` + sfnOrders + `"`,
	}
	if start != "" {
		fields = append(fields, `"startDate":`+start)
	}
	if stop != "" {
		fields = append(fields, `"stopDate":`+stop)
	}
	if redrive != "" {
		fields = append(fields, `"redriveDate":`+redrive)
	}
	return `{"executions":[{` + strings.Join(fields, ",") + `}]}`
}

const sfnNoExecutions = `{"executions":[]}`

// sfnExecutionsByMachine answers ListExecutions per state machine ARN.
func sfnExecutionsByMachine(t *testing.T, responses map[string]string) func(string) fakeAWSResponse {
	return func(body string) fakeAWSResponse {
		arn, ok := sfnRequestARN(t, "ListExecutions", body)
		if !ok {
			return sfnUnexpected()
		}
		resp, found := responses[arn]
		if !found {
			assert.Fail(t, "unexpected ListExecutions", "state machine %q", arn)
			return sfnUnexpected()
		}
		return fakeAWSResponse{status: http.StatusOK, body: resp}
	}
}

// sfnRequestARN reads the request's stateMachineArn. These handlers run on the
// SDK's goroutine, where require's FailNow would hang the pipeline instead of
// failing the test, so an unexpected call is reported with assert and answered
// with an error the enumerator can surface.
func sfnRequestARN(t *testing.T, operation, body string) (string, bool) {
	var input struct {
		StateMachineArn string `json:"stateMachineArn"`
	}
	if err := json.Unmarshal([]byte(body), &input); err != nil {
		assert.Fail(t, "undecodable request body", "%s: %v", operation, err)
		return "", false
	}
	return input.StateMachineArn, true
}

func sfnUnexpected() fakeAWSResponse {
	return fakeAWSResponse{status: http.StatusBadRequest, body: jsonError("UnexpectedCall")}
}

func newSFNFixture(t *testing.T) (*fakeAWS, *SkipReport, *SFNStateMachineEnumerator) {
	fake := newFakeAWS(t)
	provider := newFakeProvider(fake, "us-east-1")
	skipReport := NewSkipReport()
	return fake, skipReport, NewSFNStateMachineEnumerator(provider.AWSCommonRecon, provider, skipReport)
}

// byARN keys resources by ARN, the identity Guard stores; ResourceID is the
// state machine's name.
func byARN(resources []output.AWSResource) map[string]output.AWSResource {
	m := make(map[string]output.AWSResource, len(resources))
	for _, r := range resources {
		m[r.ARN] = r
	}
	return m
}

func TestSFNStateMachineLastModified_UsesLaterOfNewestExecutionStartAndStop(t *testing.T) {
	start := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	stop := time.Date(2026, 9, 1, 11, 30, 0, 0, time.UTC)
	redriven := time.Date(2026, 9, 2, 8, 15, 0, 0, time.UTC)
	created := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name       string
		executions string
		want       time.Time
	}{
		{name: "stopped execution uses stop time", executions: sfnExecution(epoch(start), epoch(stop)), want: stop},
		{name: "running execution uses start time", executions: sfnExecution(epoch(start), ""), want: start},
		// AWS sorts a redriven running execution by its redriveDate, so that is
		// the key the first result was chosen by: ignoring it would report a
		// time earlier than an execution AWS ranked below this one, and Guard
		// would skip content that had in fact changed.
		{
			name:       "redriven running execution uses redrive time",
			executions: sfnRedrivenExecution(epoch(start), "", epoch(redriven)),
			want:       redriven,
		},
		{
			name:       "redrive time older than the stop time is ignored",
			executions: sfnRedrivenExecution(epoch(start), epoch(stop), epoch(start.Add(time.Minute))),
			want:       stop,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fake, _, enum := newSFNFixture(t)
			fake.reply("ListStateMachines", sfnListStateMachines(sfnOrders))
			fake.reply("DescribeStateMachine", sfnDescribe(sfnOrders, epoch(created)))
			fake.on("ListExecutions", sfnExecutionsByMachine(t, map[string]string{sfnOrders: tc.executions}))

			resources, err := collectFakeResources(t, enum.EnumerateAll)

			require.NoError(t, err)
			require.Len(t, resources, 1)
			require.NotNil(t, resources[0].LastModified)
			assert.Equal(t, tc.want, resources[0].LastModified.UTC())
			assert.Equal(t, sfnOrders, resources[0].ARN)
			assert.Equal(t, "orders", resources[0].ResourceID, "the native enumerator keys ResourceID by name")

			requests := fake.requests("ListExecutions")
			require.Len(t, requests, 1)
			var input map[string]any
			require.NoError(t, json.Unmarshal([]byte(requests[0]), &input))
			assert.Equal(t, sfnOrders, input["stateMachineArn"], "the state machine is looked up by ARN, not name")
			assert.EqualValues(t, 1, input["maxResults"], "only the newest execution is read")
		})
	}
}

func TestSFNStateMachineLastModified_NoExecutionsFallsBackToCreationDate(t *testing.T) {
	created := time.Date(2025, 4, 2, 3, 4, 5, 0, time.UTC)
	start := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)

	fake, _, enum := newSFNFixture(t)
	fake.reply("ListStateMachines", sfnListStateMachines(sfnOrders, sfnIdle))
	fake.on("DescribeStateMachine", sfnDescribeByMachine(t, map[string]string{
		sfnOrders: epoch(start),
		sfnIdle:   epoch(created),
	}))
	fake.on("ListExecutions", sfnExecutionsByMachine(t, map[string]string{
		sfnOrders: sfnExecution(epoch(start), ""),
		sfnIdle:   sfnNoExecutions,
	}))

	resources, err := collectFakeResources(t, enum.EnumerateAll)

	require.NoError(t, err)
	got := byARN(resources)
	require.Len(t, got, 2)
	require.NotNil(t, got[sfnIdle].LastModified)
	assert.Equal(t, created, got[sfnIdle].LastModified.UTC(), "a machine that never ran keeps its CreationDate")
	require.NotNil(t, got[sfnOrders].LastModified)
	assert.Equal(t, start, got[sfnOrders].LastModified.UTC())
}

func TestSFNStateMachineLastModified_MissingContractedFieldEmitsStateMachineUnstamped(t *testing.T) {
	start := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)

	tests := []struct {
		name         string
		executions   string
		creationDate string
		wantErrField string
	}{
		{
			name:         "execution without StartDate",
			executions:   sfnExecution("", epoch(start)),
			creationDate: epoch(start),
			wantErrField: "StartDate",
		},
		{
			name:         "described state machine without CreationDate",
			executions:   sfnNoExecutions,
			creationDate: "",
			wantErrField: "CreationDate",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logs := captureLogs(t)
			fake, _, enum := newSFNFixture(t)
			fake.reply("ListStateMachines", sfnListStateMachines(sfnOrders))
			fake.reply("DescribeStateMachine", sfnDescribe(sfnOrders, tc.creationDate))
			fake.on("ListExecutions", sfnExecutionsByMachine(t, map[string]string{sfnOrders: tc.executions}))

			resources, err := collectFakeResources(t, enum.EnumerateAll)

			require.NoError(t, err, "a missing contracted field must not fail the region listing")
			require.Len(t, resources, 1, "the state machine is still emitted")
			assert.Equal(t, sfnOrders, resources[0].ARN)
			assert.Nil(t, resources[0].LastModified, "an unstampable state machine is always scanned")

			failures := logs.timestampFailures(slog.LevelError)
			require.Len(t, failures, 1)
			assert.Equal(t, sfnOrders, failures[0].attrs["arn"])
			assert.Contains(t, failures[0].attrs["error"], tc.wantErrField)
		})
	}
}

// One state machine in the region lacks its contracted CreationDate; only it
// loses LastModified, its neighbour is stamped, and the listing succeeds.
func TestSFNStateMachineLastModified_MissingFieldIsIsolatedToThatResource(t *testing.T) {
	logs := captureLogs(t)
	created := time.Date(2025, 4, 2, 3, 4, 5, 0, time.UTC)

	fake, _, enum := newSFNFixture(t)
	fake.reply("ListStateMachines", sfnListStateMachines(sfnOrders, sfnIdle))
	fake.on("DescribeStateMachine", sfnDescribeByMachine(t, map[string]string{
		sfnOrders: epoch(created),
		sfnIdle:   "",
	}))
	fake.on("ListExecutions", sfnExecutionsByMachine(t, map[string]string{
		sfnOrders: sfnNoExecutions,
		sfnIdle:   sfnNoExecutions,
	}))

	resources, err := collectFakeResources(t, enum.EnumerateAll)

	require.NoError(t, err)
	got := byARN(resources)
	require.Len(t, got, 2, "both state machines are emitted")
	require.Contains(t, got, sfnOrders)
	require.Contains(t, got, sfnIdle)
	require.NotNil(t, got[sfnOrders].LastModified, "the healthy neighbour keeps its timestamp")
	assert.Equal(t, created, got[sfnOrders].LastModified.UTC())
	assert.Nil(t, got[sfnIdle].LastModified, "only the resource missing CreationDate is unstamped")

	failures := logs.timestampFailures(slog.LevelError)
	require.Len(t, failures, 1, "exactly the bad resource is logged")
	assert.Equal(t, sfnIdle, failures[0].attrs["arn"])
	assert.Equal(t, "idle", failures[0].attrs["resource_id"])
	assert.Equal(t, "AWS::StepFunctions::StateMachine", failures[0].attrs["resource_type"])
	assert.Equal(t, "us-east-1", failures[0].attrs["region"])
}

func TestSFNStateMachineLastModified_ListExecutionsFailureLeavesStateMachineUnstamped(t *testing.T) {
	created := time.Date(2025, 4, 2, 3, 4, 5, 0, time.UTC)

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
			fake, skipReport, enum := newSFNFixture(t)
			fake.reply("ListStateMachines", sfnListStateMachines(sfnOrders))
			fake.reply("DescribeStateMachine", sfnDescribe(sfnOrders, epoch(created)))
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

func TestSFNStateMachineLastModified_EnumerateByARN(t *testing.T) {
	created := time.Date(2025, 4, 2, 3, 4, 5, 0, time.UTC)

	t.Run("no executions uses DescribeStateMachine CreationDate", func(t *testing.T) {
		fake, _, enum := newSFNFixture(t)
		fake.reply("DescribeStateMachine", sfnDescribe(sfnIdle, epoch(created)))
		fake.on("ListExecutions", sfnExecutionsByMachine(t, map[string]string{sfnIdle: sfnNoExecutions}))

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
		fake, _, enum := newSFNFixture(t)
		fake.reply("DescribeStateMachine", sfnDescribe(sfnIdle, ""))
		fake.on("ListExecutions", sfnExecutionsByMachine(t, map[string]string{sfnIdle: sfnNoExecutions}))

		resources, err := collectFakeResources(t, func(out *pipeline.P[output.AWSResource]) error {
			return enum.EnumerateByARN(sfnIdle, out)
		})

		require.NoError(t, err)
		require.Len(t, resources, 1, "the state machine is still emitted")
		assert.Equal(t, sfnIdle, resources[0].ARN)
		assert.Nil(t, resources[0].LastModified)

		failures := logs.timestampFailures(slog.LevelError)
		require.Len(t, failures, 1)
		assert.Equal(t, sfnIdle, failures[0].attrs["arn"])
		assert.Contains(t, failures[0].attrs["error"], "CreationDate")
	})
}
