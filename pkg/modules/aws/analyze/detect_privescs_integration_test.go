//go:build integration

package analyze

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/graph/queries/enrich/aws/privesc"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "github.com/praetorian-inc/aurelian/pkg/modules/aws/recon"
)

var sharedNeo4jBoltURL string

func TestMain(m *testing.M) {
	ctx := context.Background()
	boltURL, cleanup, err := testutil.StartNeo4jContainer(ctx)
	if err != nil {
		slog.Error("failed to start integration test Neo4j container", "error", err)
		os.Exit(1)
	}
	sharedNeo4jBoltURL = boltURL

	code := m.Run()
	cleanup()
	os.Exit(code)
}

func TestDetectPrivescs(t *testing.T) {
	// -------------------------------------------------------------------------
	// Step 1: Deploy the shared graph fixture (reuses aws/recon/graph).
	// -------------------------------------------------------------------------
	fixture := testutil.NewAWSFixture(t, "aws/recon/graph")
	fixture.Setup()

	// -------------------------------------------------------------------------
	// Step 2: Run the graph recon module to collect IAM entities & relationships.
	// -------------------------------------------------------------------------
	graphMod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "graph")
	require.True(t, ok, "graph recon module not registered")

	graphCfg := plugin.Config{
		Args: map[string]any{
			"regions": []string{"us-east-2"},
		},
		Context: context.Background(),
	}
	p1 := pipeline.From(graphCfg)
	p2 := pipeline.New[model.AurelianModel]()
	pipeline.Pipe(p1, graphMod.Run, p2)

	var graphResults []model.AurelianModel
	for m := range p2.Range() {
		graphResults = append(graphResults, m)
	}
	require.NoError(t, p2.Wait())
	require.NotEmpty(t, graphResults, "graph module should emit results")

	// -------------------------------------------------------------------------
	// Step 3: Load graph data into Neo4j via GraphFormatter.
	// -------------------------------------------------------------------------
	testutil.ClearNeo4jDatabase(t, sharedNeo4jBoltURL)

	formatter, err := plugin.NewGraphFormatter(sharedNeo4jBoltURL, "", "")
	require.NoError(t, err)
	defer formatter.Close()

	err = formatter.Format(graphResults)
	require.NoError(t, err, "graph formatter should load data into Neo4j")

	// -------------------------------------------------------------------------
	// Step 4: Run detect-privescs against the populated graph.
	// -------------------------------------------------------------------------
	detectMod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryAnalyze, "detect-privescs")
	require.True(t, ok, "detect-privescs module not registered")

	detectCfg := plugin.Config{
		Args: map[string]any{
			"neo4j-uri":      sharedNeo4jBoltURL,
			"neo4j-username": "",
			"neo4j-password": "",
		},
		Context: context.Background(),
	}

	out := pipeline.New[model.AurelianModel]()
	go func() {
		defer out.Close()
		err := detectMod.Run(detectCfg, out)
		require.NoError(t, err)
	}()

	var risks []output.AurelianRisk
	for m := range out.Range() {
		if risk, ok := m.(output.AurelianRisk); ok {
			risks = append(risks, risk)
		}
	}

	// Index risks by method ID for targeted assertions.
	risksByMethod := make(map[string][]output.AurelianRisk)
	for _, r := range risks {
		risksByMethod[r.Name] = append(risksByMethod[r.Name], r)
	}

	// -------------------------------------------------------------------------
	// Step 5: Assert on detected privilege escalation risks.
	// -------------------------------------------------------------------------

	t.Run("emits risks for all registered methods", func(t *testing.T) {
		for _, method := range privesc.AllPrivescQueries {
			assert.NotEmpty(t, risksByMethod[method.Name()],
				"should detect risks for %s", method.Name())
		}
	})

	for _, method := range privesc.AllPrivescQueries {
		method := method
		t.Run(method.Name(), func(t *testing.T) {
			methodRisks := risksByMethod[method.Name()]
			require.NotEmpty(t, methodRisks, "no risks for %s", method.Name())
			assert.GreaterOrEqual(t, len(methodRisks), 1)
			assert.Equal(t, output.RiskSeverityHigh, methodRisks[0].Severity)
		})
	}

	t.Run("all risks have valid deduplication IDs", func(t *testing.T) {
		for _, risk := range risks {
			assert.NotEmpty(t, risk.DeduplicationID)
			assert.Len(t, risk.DeduplicationID, 64, "SHA-256 hex should be 64 chars")
		}
	})

	t.Run("all risks have matched path context with hops", func(t *testing.T) {
		for _, risk := range risks {
			var ctxs []map[string]interface{}
			err := json.Unmarshal(risk.Context, &ctxs)
			require.NoError(t, err, "risk context should be valid JSON")

			for i, ctx := range ctxs {
				sourceID, ok := ctx["source_id"].(string)
				require.True(t, ok, "source id did not exist in context %d: %v", i, ctx)
				require.NotEmpty(t, sourceID, "source id was an empty string in context %d: %v", i, ctx)

				targetID, ok := ctx["target_id"].(string)
				require.True(t, ok, "target id did not exist in context %d: %v", i, ctx)
				require.NotEmpty(t, targetID, "target id was an empty string in context %d: %v", i, ctx)

				actions, ok := ctx["actions"].([]any)
				require.True(t, ok, "actions did not exist in context %d: %v", i, ctx)
				require.NotEmpty(t, actions, "actions was an empty slice in context %d: %v", i, ctx)
			}
		}
	})

	t.Run("diagnostic summary", func(t *testing.T) {
		t.Logf("Total risks detected: %d", len(risks))
		for method, methodRisks := range risksByMethod {
			t.Logf("  %s: %d risks", method, len(methodRisks))
		}
	})
}
