package publicaccess

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEvaluate_NoRisk(t *testing.T) {
	ev := AccessEvaluator{}
	out := pipeline.New[model.AurelianModel]()
	go func() {
		defer out.Close()
		err := ev.Evaluate(output.NewGCPResource("proj", "storage.googleapis.com/Bucket", "id"), out)
		assert.NoError(t, err)
	}()
	items, err := out.Collect()
	require.NoError(t, err)
	assert.Len(t, items, 1) // just the resource, no risk
}

func TestEvaluate_PublicNetwork(t *testing.T) {
	ev := AccessEvaluator{}
	out := pipeline.New[model.AurelianModel]()
	r := output.NewGCPResource("proj", "compute.googleapis.com/Instance", "id")
	r.IPs = []string{"1.2.3.4"}
	go func() {
		defer out.Close()
		err := ev.Evaluate(r, out)
		assert.NoError(t, err)
	}()
	items, err := out.Collect()
	require.NoError(t, err)
	assert.Len(t, items, 2) // resource + risk
}

func TestEvaluate_AnonymousAccess(t *testing.T) {
	ev := AccessEvaluator{}
	out := pipeline.New[model.AurelianModel]()
	r := output.NewGCPResource("proj", "cloudfunctions.googleapis.com/Function", "id")
	r.Properties = map[string]any{"AnonymousAccess": true}
	go func() {
		defer out.Close()
		err := ev.Evaluate(r, out)
		assert.NoError(t, err)
	}()
	items, err := out.Collect()
	require.NoError(t, err)
	assert.Len(t, items, 2)
}

func TestEvaluate_BothPublicAndAnonymous_HighSeverity(t *testing.T) {
	ev := AccessEvaluator{}
	out := pipeline.New[model.AurelianModel]()
	r := output.NewGCPResource("proj", "run.googleapis.com/Service", "id")
	r.URLs = []string{"https://my-svc.run.app"}
	r.Properties = map[string]any{"AnonymousAccess": true}
	go func() {
		defer out.Close()
		err := ev.Evaluate(r, out)
		assert.NoError(t, err)
	}()
	items, err := out.Collect()
	require.NoError(t, err)
	require.Len(t, items, 2)
	risk, ok := items[1].(output.AurelianRisk)
	require.True(t, ok)
	assert.Equal(t, output.RiskSeverityHigh, risk.Severity)
	assert.Equal(t, "public-anonymous-gcp-resource-run-service", risk.Name)
	assert.Equal(t, "run.googleapis.com/Service", risk.DeduplicationID)
}

func TestEvaluate_GranularRiskName(t *testing.T) {
	tests := []struct {
		name         string
		resource     output.GCPResource
		wantRiskName string
		wantDedupeID string
		wantSeverity output.RiskSeverity
	}{
		{
			name: "public+anonymous compute instance",
			resource: output.GCPResource{
				ResourceType: "compute.googleapis.com/Instance",
				ResourceID:   "projects/p/zones/z/instances/i",
				ProjectID:    "p",
				IPs:          []string{"1.2.3.4"},
				Properties:   map[string]any{"AnonymousAccess": true},
			},
			wantRiskName: "public-anonymous-gcp-resource-compute-instance",
			wantDedupeID: "compute.googleapis.com/Instance",
			wantSeverity: output.RiskSeverityHigh,
		},
		{
			name: "anonymous-only storage bucket",
			resource: output.GCPResource{
				ResourceType: "storage.googleapis.com/Bucket",
				ResourceID:   "projects/_/buckets/b",
				ProjectID:    "p",
				Properties:   map[string]any{"AnonymousAccess": true},
			},
			wantRiskName: "anonymous-gcp-resource-storage-bucket",
			wantDedupeID: "storage.googleapis.com/Bucket",
			wantSeverity: output.RiskSeverityMedium,
		},
		{
			name: "public-only cloud run service",
			resource: output.GCPResource{
				ResourceType: "run.googleapis.com/Service",
				ResourceID:   "projects/p/locations/l/services/s",
				ProjectID:    "p",
				URLs:         []string{"https://s.run.app"},
			},
			wantRiskName: "public-gcp-resource-run-service",
			wantDedupeID: "run.googleapis.com/Service",
			wantSeverity: output.RiskSeverityMedium,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &AccessEvaluator{}
			out := pipeline.New[model.AurelianModel]()

			go func() {
				defer out.Close()
				e.Evaluate(tt.resource, out)
			}()

			items, err := out.Collect()
			require.NoError(t, err)

			// First item is the resource itself, second is the risk.
			var risk output.AurelianRisk
			for _, item := range items {
				if r, ok := item.(output.AurelianRisk); ok {
					risk = r
				}
			}

			assert.Equal(t, tt.wantRiskName, risk.Name)
			assert.Equal(t, tt.wantDedupeID, risk.DeduplicationID)
			assert.Equal(t, tt.wantSeverity, risk.Severity)
		})
	}
}
