package extraction

import (
	"testing"
	"time"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestModifiedSinceFilter_SSMParameter(t *testing.T) {
	since := time.Date(2026, time.August, 24, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name          string
		modifiedAt    string
		wantRescanned bool
	}{
		{name: "older resource is skipped", modifiedAt: since.Add(-time.Hour).Format(time.RFC3339Nano)},
		{name: "same timestamp is skipped", modifiedAt: since.Format(time.RFC3339Nano)},
		{name: "newer resource is rescanned", modifiedAt: since.Add(time.Second).Format(time.RFC3339Nano), wantRescanned: true},
		{name: "missing timestamp fails open", wantRescanned: true},
		{name: "invalid timestamp fails open", modifiedAt: "not-a-time", wantRescanned: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			filter := NewModifiedSinceFilter(plugin.AWSCommonRecon{}, since)
			resource := output.AWSResource{
				ResourceType: "AWS::SSM::Parameter",
				ResourceID:   "/example",
				Properties:   map[string]any{"LastModifiedDate": test.modifiedAt},
			}

			items := runModifiedSinceFilter(t, filter, resource)
			if test.wantRescanned {
				require.Len(t, items, 1)
				assert.Equal(t, resource.ResourceID, items[0].ResourceID)
				return
			}
			assert.Empty(t, items)
		})
	}
}

func TestModifiedSinceFilter_UnsupportedTypeFailsOpen(t *testing.T) {
	filter := NewModifiedSinceFilter(plugin.AWSCommonRecon{}, time.Now().UTC())
	resource := output.AWSResource{ResourceType: "AWS::EC2::Instance", ResourceID: "i-123"}

	items := runModifiedSinceFilter(t, filter, resource)

	require.Len(t, items, 1)
	assert.Equal(t, resource.ResourceID, items[0].ResourceID)
}

func TestParseAWSTimestamp_LambdaFormat(t *testing.T) {
	parsed, err := parseAWSTimestamp("2026-08-24T12:34:56.789+0000")
	require.NoError(t, err)
	assert.Equal(t, "2026-08-24T12:34:56.789Z", parsed.Format(time.RFC3339Nano))
}

func runModifiedSinceFilter(t *testing.T, filter *ModifiedSinceFilter, resource output.AWSResource) []output.AWSResource {
	t.Helper()
	out := pipeline.New[output.AWSResource]()
	go func() {
		if err := filter.Filter(resource, out); err != nil {
			out.CloseWithError(err)
			return
		}
		out.Close()
	}()
	items, err := out.Collect()
	require.NoError(t, err)
	return items
}
