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

	t.Run("detects outdated bootstrap version", func(t *testing.T) {
		var found bool
		for _, risk := range risks {
			if risk.Name == "cdk-bootstrap-outdated" {
				found = true
				assert.Equal(t, "TH", risk.Status)
				assert.Equal(t, "aurelian-cdk-scanner", risk.Source)
				assert.Contains(t, risk.Description, "20")
				break
			}
		}
		assert.True(t, found, "expected cdk-bootstrap-outdated risk")
	})

	t.Run("detects missing bootstrap version", func(t *testing.T) {
		var found bool
		for _, risk := range risks {
			if risk.Name == "cdk-bootstrap-missing" {
				found = true
				assert.Equal(t, "TM", risk.Status)
				assert.Equal(t, "aurelian-cdk-scanner", risk.Source)
				assert.Contains(t, risk.Description, "not found")
				break
			}
		}
		assert.True(t, found, "expected cdk-bootstrap-missing risk from qualifier with no SSM param")
	})

	t.Run("detects missing bucket takeover", func(t *testing.T) {
		var found bool
		for _, risk := range risks {
			if risk.Name == "cdk-bucket-takeover" {
				found = true
				assert.Equal(t, "TH", risk.Status)
				assert.Equal(t, "aurelian-cdk-scanner", risk.Source)
				assert.Contains(t, risk.Description, "missing")
				break
			}
		}
		assert.True(t, found, "expected cdk-bucket-takeover risk from qualifier with no S3 bucket")
	})

	t.Run("detects unrestricted policy on file publishing role", func(t *testing.T) {
		var found bool
		for _, risk := range risks {
			if risk.Name == "cdk-policy-unrestricted" {
				found = true
				assert.Equal(t, "TM", risk.Status)
				assert.Equal(t, "aurelian-cdk-scanner", risk.Source)
				assert.Contains(t, risk.Description, "FilePublishingRole")
				break
			}
		}
		assert.True(t, found, "expected cdk-policy-unrestricted risk")
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
		_, _ = p2.Collect()
	})
}
