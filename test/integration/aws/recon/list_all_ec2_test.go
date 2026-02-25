//go:build integration

package recon

import (
	"context"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/model"
	_ "github.com/praetorian-inc/aurelian/pkg/modules/aws/recon" // register modules
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/require"
)

func TestAWSListAllEC2Instances(t *testing.T) {
	fixture := testutil.NewFixture(t, "aws/recon/list")
	fixture.Setup()

	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "list-all")
	if !ok {
		t.Skip("list-all module not registered in plugin system")
	}

	cfg := plugin.Config{
		Args: map[string]any{
			"resource-type": []string{"AWS::EC2::Instance"},
			"regions":       []string{"us-east-2"},
			"scan-type":     "full",
		},
		Context: context.Background(),
	}
	p1 := pipeline.From(cfg)
	p2 := pipeline.New[model.AurelianModel]()
	pipeline.Pipe(p1, mod.Run, p2)

	results, err := p2.Collect()
	require.NoError(t, err)

	testutil.AssertMinResults(t, results, 1)

	for _, id := range fixture.OutputList("instance_ids") {
		testutil.AssertResultContainsString(t, results, id)
	}
}
