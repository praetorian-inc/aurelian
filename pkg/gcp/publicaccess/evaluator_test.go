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
}
