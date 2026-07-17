//go:build integration

package recon

import (
	"context"
	"strings"
	"testing"

	_ "github.com/praetorian-inc/aurelian/pkg/modules/aws/enrichers" // register enrichers
	_ "github.com/praetorian-inc/aurelian/pkg/modules/aws/recon"     // register modules
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigurationScanIMDSRisk(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/ec2-imds-check")
	fixture.Setup()

	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "configuration-scan")
	require.True(t, ok, "configuration-scan module not registered")

	results, err := testutil.RunAndCollect(t, mod, plugin.Config{
		Args: map[string]any{
			"resource-type": []string{"AWS::EC2::Instance"},
			"regions":       []string{"us-east-1"},
		},
		Context: context.Background(),
	})
	require.NoError(t, err)

	flagged := fixture.OutputList("flagged_instance_ids")
	safe := fixture.OutputList("safe_instance_ids")
	require.NotEmpty(t, flagged, "fixture must define flagged instances")

	riskedARNs := []string{}
	for _, r := range results {
		risk, ok := r.(output.AurelianRisk)
		if !ok {
			continue
		}
		assert.Equal(t, "ec2-imdsv1-enabled", risk.Name)
		assert.Equal(t, output.RiskSeverityMedium, risk.Severity)
		riskedARNs = append(riskedARNs, risk.ImpactedResourceID)
	}

	arnRisked := func(instanceID string) bool {
		for _, arn := range riskedARNs {
			if strings.Contains(arn, instanceID) {
				return true
			}
		}
		return false
	}

	for _, id := range flagged {
		assert.True(t, arnRisked(id), "flagged instance %s should yield a risk", id)
	}
	for _, id := range safe {
		assert.False(t, arnRisked(id), "safe instance %s must not yield a risk", id)
	}
}
