package enumeration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const ssmListOneDocument = `{"DocumentIdentifiers":[{"Name":"deploy","Owner":"123456789012","DocumentVersion":"3","DocumentType":"Command","CreatedDate":1600000000}]}`

func ssmDescribeDocument(createdDate time.Time) string {
	return fmt.Sprintf(`{"Document":{"Name":"deploy","Owner":"123456789012","DocumentVersion":"2","DocumentType":"Command","CreatedDate":%d}}`, createdDate.Unix())
}

func newSSMDocumentFixture(t *testing.T) (*fakeAWS, *SkipReport, *SSMDocumentEnumerator) {
	fake := newFakeAWS(t)
	provider := newFakeProvider(fake, "us-east-1")
	skipReport := NewSkipReport()
	return fake, skipReport, NewSSMDocumentEnumerator(provider.AWSCommonRecon, provider, skipReport)
}

func TestSSMDocument_ListStampsDefaultVersionCreatedDate(t *testing.T) {
	defaultCreated := time.Date(2026, 8, 8, 8, 8, 8, 0, time.UTC)
	fake, skipReport, enum := newSSMDocumentFixture(t)
	fake.reply("ListDocuments", ssmListOneDocument)
	fake.reply("DescribeDocument", ssmDescribeDocument(defaultCreated))

	resources, err := collectResources(t, enum.EnumerateAll)

	require.NoError(t, err)
	require.Len(t, resources, 1)
	require.NotNil(t, resources[0].LastModified)
	assert.Equal(t, defaultCreated, resources[0].LastModified.UTC(),
		"LastModified is the default version's CreatedDate, not ListDocuments' CreatedDate")
	assert.Equal(t, "3", resources[0].Properties["DocumentVersion"], "Properties still come from ListDocuments")
	assert.Zero(t, skipReport.Len())

	requests := fake.requests("DescribeDocument")
	require.Len(t, requests, 1)
	var input map[string]any
	require.NoError(t, json.Unmarshal([]byte(requests[0]), &input))
	assert.Equal(t, "deploy", input["Name"])
	assert.Equal(t, "$DEFAULT", input["DocumentVersion"])
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

			resources, err := collectResources(t, enum.EnumerateAll)

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

func TestSSMDocument_EnumerateByARNStampsDescribedCreatedDate(t *testing.T) {
	defaultCreated := time.Date(2026, 8, 8, 8, 8, 8, 0, time.UTC)
	fake, _, enum := newSSMDocumentFixture(t)
	fake.reply("DescribeDocument", ssmDescribeDocument(defaultCreated))

	resources, err := collectResources(t, func(out *pipeline.P[output.AWSResource]) error {
		return enum.EnumerateByARN("arn:aws:ssm:us-east-1:123456789012:document/deploy", out)
	})

	require.NoError(t, err)
	require.Len(t, resources, 1)
	require.NotNil(t, resources[0].LastModified)
	assert.Equal(t, defaultCreated, resources[0].LastModified.UTC())
}
