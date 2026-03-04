//go:build integration

package recon

import (
	"context"
	"testing"

	"github.com/praetorian-inc/aurelian/test/testutil"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/require"
)

func runAndCollect(t *testing.T, mod plugin.Module, cfg plugin.Config) ([]model.AurelianModel, error) {
	t.Helper()
	p1 := pipeline.From(cfg)
	p2 := pipeline.New[model.AurelianModel]()
	pipeline.Pipe(p1, mod.Run, p2)

	return p2.Collect()
}

func TestAWSList(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/list")
	fixture.Setup()

	t.Run("EC2 instances", func(t *testing.T) {
		mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "list-all")
		if !ok {
			t.Skip("list-all module not registered in plugin system")
		}

		results, err := runAndCollect(t, mod, plugin.Config{
			Args: map[string]any{
				"resource-type": []string{"AWS::EC2::Instance"},
				"regions":       []string{"us-east-2"},
				"scan-type":     "full",
			},
			Context: context.Background(),
		})
		require.NoError(t, err)
		testutil.AssertMinResults(t, results, 1)

		for _, id := range fixture.OutputList("instance_ids") {
			testutil.AssertResultContainsString(t, results, id)
		}
	})

	t.Run("S3 buckets", func(t *testing.T) {
		mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "list-all")
		if !ok {
			t.Skip("list-all module not registered in plugin system")
		}

		results, err := runAndCollect(t, mod, plugin.Config{
			Args: map[string]any{
				"resource-type": []string{"AWS::S3::Bucket"},
				"regions":       []string{"us-east-2"},
				"scan-type":     "full",
			},
			Context: context.Background(),
		})
		require.NoError(t, err)
		testutil.AssertMinResults(t, results, 1)

		for _, name := range fixture.OutputList("bucket_names") {
			testutil.AssertResultContainsString(t, results, name)
		}
	})

	t.Run("Lambda functions", func(t *testing.T) {
		mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "list-all")
		if !ok {
			t.Skip("list-all module not registered in plugin system")
		}

		results, err := runAndCollect(t, mod, plugin.Config{
			Args: map[string]any{
				"resource-type": []string{"AWS::Lambda::Function"},
				"regions":       []string{"us-east-2"},
				"scan-type":     "full",
			},
			Context: context.Background(),
		})
		require.NoError(t, err)
		testutil.AssertMinResults(t, results, 1)

		for _, arn := range fixture.OutputList("function_arns") {
			testutil.AssertResultContainsARN(t, results, arn)
		}
	})
}
