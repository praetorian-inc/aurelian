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

const ssmListOneDocument = `{"DocumentIdentifiers":[{"Name":"deploy","Owner":"123456789012","DocumentVersion":"3","DocumentType":"Command","CreatedDate":1600000000}]}`

func ssmDescribeDocument(version string, createdDate time.Time) string {
	return fmt.Sprintf(`{"Document":{"Name":"deploy","Owner":"123456789012","DocumentVersion":%q,"DocumentType":"Command","CreatedDate":%d}}`, version, createdDate.Unix())
}

// replyDescribeByVersion answers DescribeDocument according to the requested
// DocumentVersion selector, so a test can tell which selector fed which field.
func replyDescribeByVersion(t *testing.T, fake *fakeAWS, bySelector map[string]string) {
	fake.on("DescribeDocument", func(body string) fakeAWSResponse {
		var input map[string]any
		if err := json.Unmarshal([]byte(body), &input); err != nil {
			return fakeAWSResponse{status: http.StatusBadRequest, body: jsonError("ValidationException")}
		}
		selector, _ := input["DocumentVersion"].(string)
		resp, ok := bySelector[selector]
		if !ok {
			assert.Fail(t, "unexpected DescribeDocument selector", "%q", selector)
			return fakeAWSResponse{status: http.StatusBadRequest, body: jsonError("ValidationException")}
		}
		return fakeAWSResponse{status: http.StatusOK, body: resp}
	})
}

func describeSelectors(t *testing.T, requests []string) []string {
	t.Helper()
	var selectors []string
	for _, r := range requests {
		var input map[string]any
		require.NoError(t, json.Unmarshal([]byte(r), &input))
		assert.Equal(t, "deploy", input["Name"])
		selectors = append(selectors, fmt.Sprint(input["DocumentVersion"]))
	}
	return selectors
}

func newSSMDocumentFixture(t *testing.T) (*fakeAWS, *SkipReport, *SSMDocumentEnumerator) {
	fake := newFakeAWS(t)
	provider := newFakeProvider(fake, "us-east-1")
	skipReport := NewSkipReport()
	return fake, skipReport, NewSSMDocumentEnumerator(provider.AWSCommonRecon, provider, skipReport)
}

func TestSSMDocument_ListStampsLatestVersionCreatedDate(t *testing.T) {
	latestCreated := time.Date(2026, 8, 8, 8, 8, 8, 0, time.UTC)
	fake, skipReport, enum := newSSMDocumentFixture(t)
	fake.reply("ListDocuments", ssmListOneDocument)
	replyDescribeByVersion(t, fake, map[string]string{
		"$LATEST": ssmDescribeDocument("5", latestCreated),
	})

	resources, err := collectFakeResources(t, enum.EnumerateAll)

	require.NoError(t, err)
	require.Len(t, resources, 1)
	require.NotNil(t, resources[0].LastModified)
	assert.Equal(t, latestCreated, resources[0].LastModified.UTC(),
		"LastModified is the $LATEST version's CreatedDate, not ListDocuments' CreatedDate")
	assert.Equal(t, "3", resources[0].Properties["DocumentVersion"], "Properties still come from ListDocuments")
	assert.Zero(t, skipReport.Len())

	assert.Equal(t, []string{"$LATEST"}, describeSelectors(t, fake.requests("DescribeDocument")))
}

func TestSSMDocument_DescribeFailureLeavesDocumentUnstampedButEmitted(t *testing.T) {
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
			fake, skipReport, enum := newSSMDocumentFixture(t)
			fake.reply("ListDocuments", ssmListOneDocument)
			fake.fail("DescribeDocument", http.StatusBadRequest, jsonError(tc.code))

			resources, err := collectFakeResources(t, enum.EnumerateAll)

			require.NoError(t, err)
			require.Len(t, resources, 1)
			assert.Nil(t, resources[0].LastModified)
			if tc.wantSkip {
				assertSkipRecorded(t, skipReport, "ssm", "DescribeDocument", "us-east-1", tc.code)
			} else {
				assert.Zero(t, skipReport.Len())
			}
		})
	}
}

func TestSSMDocument_EnumerateByARNPropertiesFromDefaultLastModifiedFromLatest(t *testing.T) {
	defaultCreated := time.Date(2026, 1, 1, 1, 1, 1, 0, time.UTC)
	latestCreated := time.Date(2026, 9, 9, 9, 9, 9, 0, time.UTC)
	fake, skipReport, enum := newSSMDocumentFixture(t)
	replyDescribeByVersion(t, fake, map[string]string{
		"$DEFAULT": ssmDescribeDocument("2", defaultCreated),
		"$LATEST":  ssmDescribeDocument("7", latestCreated),
	})

	resources, err := collectFakeResources(t, func(out *pipeline.P[output.AWSResource]) error {
		return enum.EnumerateByARN("arn:aws:ssm:us-east-1:123456789012:document/deploy", out)
	})

	require.NoError(t, err)
	assert.Zero(t, skipReport.Len())
	assert.ElementsMatch(t, []string{"$DEFAULT", "$LATEST"}, describeSelectors(t, fake.requests("DescribeDocument")))

	require.Len(t, resources, 1)
	assert.Equal(t, "2", resources[0].Properties["DocumentVersion"],
		"Properties describe the default version")
	require.NotNil(t, resources[0].LastModified)
	assert.Equal(t, latestCreated, resources[0].LastModified.UTC(),
		"LastModified is the $LATEST version's CreatedDate, not the default's")
}

func TestSSMDocument_EnumerateByARNLatestDescribeFailureLeavesUnstamped(t *testing.T) {
	fake, _, enum := newSSMDocumentFixture(t)
	fake.on("DescribeDocument", func(body string) fakeAWSResponse {
		if strings.Contains(body, `"$LATEST"`) {
			return fakeAWSResponse{status: http.StatusBadRequest, body: jsonError("ExpiredTokenException")}
		}
		return fakeAWSResponse{status: http.StatusOK, body: ssmDescribeDocument("2", time.Unix(1600000000, 0))}
	})

	resources, err := collectFakeResources(t, func(out *pipeline.P[output.AWSResource]) error {
		return enum.EnumerateByARN("arn:aws:ssm:us-east-1:123456789012:document/deploy", out)
	})

	require.NoError(t, err)
	require.Len(t, resources, 1, "document is still emitted when $LATEST describe fails")
	assert.Nil(t, resources[0].LastModified)
	assert.Equal(t, "2", resources[0].Properties["DocumentVersion"])
}
