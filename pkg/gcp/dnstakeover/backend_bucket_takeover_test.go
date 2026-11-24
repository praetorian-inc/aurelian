package dnstakeover

import (
	"encoding/json"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/compute/v1"
)

func TestNewBackendBucketRisk_HighSeverity(t *testing.T) {
	risk := newBackendBucketRisk("my-project", "my-backend", "missing-bucket", "", nil)

	assert.Equal(t, "gcp-lb-backend-bucket-takeover", risk.Name)
	assert.Equal(t, output.RiskSeverityHigh, risk.Severity)
	assert.Equal(t, "projects/my-project/global/backendBuckets/my-backend", risk.ImpactedResourceID)
	assert.Equal(t, "lb-backend-takeover:my-project:my-backend", risk.DeduplicationID)
}

func TestNewBackendBucketRisk_CriticalWhenURLMapsReference(t *testing.T) {
	risk := newBackendBucketRisk("proj", "bb", "bucket", "https://self/link", []string{"url-map-1"})

	assert.Equal(t, output.RiskSeverityCritical, risk.Severity)
	assert.Equal(t, "https://self/link", risk.ImpactedResourceID)
}

func TestNewBackendBucketRisk_DeduplicationID(t *testing.T) {
	tests := []struct {
		project string
		bbName  string
		want    string
	}{
		{"proj-a", "bb-1", "lb-backend-takeover:proj-a:bb-1"},
		{"proj-b", "bb-2", "lb-backend-takeover:proj-b:bb-2"},
	}
	for _, tt := range tests {
		risk := newBackendBucketRisk(tt.project, tt.bbName, "bucket", "", nil)
		assert.Equal(t, tt.want, risk.DeduplicationID)
	}
}

func TestNewBackendBucketRisk_ContextFields(t *testing.T) {
	risk := newBackendBucketRisk("my-project", "my-backend", "missing-bucket", "", []string{"um-1", "um-2"})

	var ctx map[string]any
	require.NoError(t, json.Unmarshal(risk.Context, &ctx))

	assert.Equal(t, "my-project", ctx["project_id"])
	assert.Equal(t, "my-backend", ctx["backend_bucket_name"])
	assert.Equal(t, "missing-bucket", ctx["gcs_bucket_name"])
	assert.NotEmpty(t, ctx["description"])
	assert.NotEmpty(t, ctx["remediation"])

	urlMaps, ok := ctx["referencing_url_maps"].([]any)
	require.True(t, ok)
	assert.Len(t, urlMaps, 2)
	assert.Equal(t, "um-1", urlMaps[0])
	assert.Equal(t, "um-2", urlMaps[1])
}

func TestReferencesBackendBucket(t *testing.T) {
	selfLink := "https://compute.googleapis.com/compute/v1/projects/p/global/backendBuckets/bb"

	tests := []struct {
		name   string
		urlMap *compute.UrlMap
		want   bool
	}{
		{
			name:   "default service matches",
			urlMap: &compute.UrlMap{DefaultService: selfLink},
			want:   true,
		},
		{
			name:   "default service does not match",
			urlMap: &compute.UrlMap{DefaultService: "other"},
			want:   false,
		},
		{
			name: "path matcher default service matches",
			urlMap: &compute.UrlMap{
				PathMatchers: []*compute.PathMatcher{
					{DefaultService: selfLink},
				},
			},
			want: true,
		},
		{
			name: "path rule service matches",
			urlMap: &compute.UrlMap{
				PathMatchers: []*compute.PathMatcher{
					{
						PathRules: []*compute.PathRule{
							{Service: selfLink},
						},
					},
				},
			},
			want: true,
		},
		{
			name:   "empty url map",
			urlMap: &compute.UrlMap{},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := referencesBackendBucket(tt.urlMap, selfLink)
			assert.Equal(t, tt.want, got)
		})
	}
}
