//go:build integration

package recon

import (
	"context"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAWSCdkBucketTakeover(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/cdk-bucket-takeover")
	fixture.Setup()

	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "cdk-bucket-takeover")
	if !ok {
		t.Fatal("cdk-bucket-takeover module not registered")
	}

	qualifier := fixture.Output("qualifier")
	qualifierNoBucket := fixture.Output("qualifier_no_bucket")
	qualifierNoSSM := fixture.Output("qualifier_no_ssm")
	accountID := fixture.Output("account_id")
	region := fixture.Output("region")

	cfg := plugin.Config{
		Args: map[string]any{
			"regions":        []string{region},
			"cdk-qualifiers": []string{qualifier, qualifierNoBucket, qualifierNoSSM},
		},
		Context: context.Background(),
	}
	p1 := pipeline.From(cfg)
	p2 := pipeline.New[model.AurelianModel]()
	pipeline.Pipe(p1, mod.Run, p2)

	results, err := p2.Collect()
	require.NoError(t, err)
	require.NotEmpty(t, results, "expected at least one result")

	var risks []output.Risk
	for _, r := range results {
		if risk, ok := r.(output.Risk); ok {
			risks = append(risks, risk)
		}
	}
	require.NotEmpty(t, risks, "expected at least one Risk result")

	// Helper to find a risk by name and qualifier.
	findRisk := func(name, qual string) *output.Risk {
		for _, risk := range risks {
			if risk.Name != name {
				continue
			}
			if risk.Target == nil || risk.Target.Properties == nil {
				continue
			}
			if risk.Target.Properties["Qualifier"] == qual {
				return &risk
			}
		}
		return nil
	}

	t.Run("detects outdated bootstrap version", func(t *testing.T) {
		risk := findRisk("cdk-bootstrap-outdated", qualifier)
		require.NotNil(t, risk, "expected cdk-bootstrap-outdated risk for qualifier %s", qualifier)
		assert.Equal(t, "TH", risk.Status)
		assert.Equal(t, "aurelian-cdk-scanner", risk.Source)
		assert.Contains(t, risk.Description, "20")
		assert.Equal(t, accountID, risk.Target.AccountRef)
		assert.Equal(t, region, risk.Target.Region)
	})

	t.Run("detects missing bootstrap version", func(t *testing.T) {
		risk := findRisk("cdk-bootstrap-missing", qualifierNoSSM)
		require.NotNil(t, risk, "expected cdk-bootstrap-missing risk for qualifier %s", qualifierNoSSM)
		assert.Equal(t, "TM", risk.Status)
		assert.Equal(t, "aurelian-cdk-scanner", risk.Source)
		assert.Contains(t, risk.Description, "not found")
		assert.Equal(t, accountID, risk.Target.AccountRef)
		assert.Equal(t, region, risk.Target.Region)
	})

	t.Run("detects missing bucket takeover", func(t *testing.T) {
		risk := findRisk("cdk-bucket-takeover", qualifierNoBucket)
		require.NotNil(t, risk, "expected cdk-bucket-takeover risk for qualifier %s", qualifierNoBucket)
		assert.Equal(t, "TH", risk.Status)
		assert.Equal(t, "aurelian-cdk-scanner", risk.Source)
		assert.Contains(t, risk.Description, "missing")
		assert.Equal(t, accountID, risk.Target.AccountRef)
		assert.Equal(t, region, risk.Target.Region)
		assert.Contains(t, risk.Target.Properties["BucketName"], qualifierNoBucket)
	})

	t.Run("detects unrestricted policy on file publishing role", func(t *testing.T) {
		risk := findRisk("cdk-policy-unrestricted", qualifier)
		require.NotNil(t, risk, "expected cdk-policy-unrestricted risk for qualifier %s", qualifier)
		assert.Equal(t, "TM", risk.Status)
		assert.Equal(t, "aurelian-cdk-scanner", risk.Source)
		assert.Contains(t, risk.Description, "FilePublishingRole")
		assert.Equal(t, accountID, risk.Target.AccountRef)
		assert.Equal(t, region, risk.Target.Region)
		assert.Contains(t, risk.Target.Properties["RoleName"], qualifier)
	})

	t.Run("all risks reference correct account and region", func(t *testing.T) {
		for _, risk := range risks {
			require.NotNil(t, risk.Target, "risk %s has nil Target", risk.Name)
			assert.Equal(t, accountID, risk.Target.AccountRef, "risk %s has wrong account", risk.Name)
			assert.Equal(t, region, risk.Target.Region, "risk %s has wrong region", risk.Name)
		}
	})

	t.Run("handles context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		cancelCfg := plugin.Config{
			Args: map[string]any{
				"regions":        []string{region},
				"cdk-qualifiers": []string{qualifier},
			},
			Context: ctx,
		}
		p1 := pipeline.From(cancelCfg)
		p2 := pipeline.New[model.AurelianModel]()
		pipeline.Pipe(p1, mod.Run, p2)
		cancelResults, cancelErr := p2.Collect()
		assert.Error(t, cancelErr, "expected error from cancelled context")
		assert.Empty(t, cancelResults, "expected no results from cancelled context")
	})
}
