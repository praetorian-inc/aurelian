//go:build integration

package analyze

import (
	"context"
	"encoding/json"
	"os"
	"testing"

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

	t.Run("emits risks for all three methods", func(t *testing.T) {
		assert.NotEmpty(t, risksByMethod["aws/enrich/privesc/method_01"],
			"should detect CreatePolicyVersion privesc paths")
		assert.NotEmpty(t, risksByMethod["aws/enrich/privesc/method_02"],
			"should detect SetDefaultPolicyVersion privesc paths")
		assert.NotEmpty(t, risksByMethod["aws/enrich/privesc/method_03"],
			"should detect CreateAccessKey privesc paths")
	})

	t.Run("method_01 CreatePolicyVersion", func(t *testing.T) {
		m01 := risksByMethod["aws/enrich/privesc/method_01"]
		require.NotEmpty(t, m01)

		// Fixture has user0 + assumable-role with iam:CreatePolicyVersion on *.
		// Each should produce at least one path to a managed policy node.
		assert.GreaterOrEqual(t, len(m01), 2,
			"user0 and assumable-role both have iam:CreatePolicyVersion")

		assert.Equal(t, output.RiskSeverityHigh, m01[0].Severity)
	})

	t.Run("method_02 SetDefaultPolicyVersion", func(t *testing.T) {
		m02 := risksByMethod["aws/enrich/privesc/method_02"]
		require.NotEmpty(t, m02)

		// user0 has iam:SetDefaultPolicyVersion on *.
		assert.GreaterOrEqual(t, len(m02), 1)
		assert.Equal(t, output.RiskSeverityHigh, m02[0].Severity)
	})

	t.Run("method_03 CreateAccessKey", func(t *testing.T) {
		m03 := risksByMethod["aws/enrich/privesc/method_03"]
		require.NotEmpty(t, m03)

		// user0 and assumable-role have iam:CreateAccessKey on *.
		// Targets are Principal nodes (users, roles, groups).
		assert.GreaterOrEqual(t, len(m03), 1)
		assert.Equal(t, output.RiskSeverityHigh, m03[0].Severity)
	})

	t.Run("all risks have valid deduplication IDs", func(t *testing.T) {
		seen := make(map[string]bool)
		for _, risk := range risks {
			assert.NotEmpty(t, risk.DeduplicationID)
			assert.Len(t, risk.DeduplicationID, 64, "SHA-256 hex should be 64 chars")
			assert.False(t, seen[risk.DeduplicationID],
				"duplicate dedup ID %s for method %s", risk.DeduplicationID, risk.Name)
			seen[risk.DeduplicationID] = true
		}
	})

	t.Run("all risks have path context with nodes and relationships", func(t *testing.T) {
		for _, risk := range risks {
			var ctx map[string]interface{}
			err := json.Unmarshal(risk.Context, &ctx)
			require.NoError(t, err, "risk context should be valid JSON")

			nodes, ok := ctx["nodes"].([]interface{})
			require.True(t, ok, "context should have 'nodes' array")
			assert.GreaterOrEqual(t, len(nodes), 2, "path should have at least 2 nodes")

			rels, ok := ctx["relationships"].([]interface{})
			require.True(t, ok, "context should have 'relationships' array")
			assert.GreaterOrEqual(t, len(rels), 1, "path should have at least 1 relationship")
		}
	})

	t.Run("diagnostic summary", func(t *testing.T) {
		t.Logf("Total risks detected: %d", len(risks))
		for method, methodRisks := range risksByMethod {
			t.Logf("  %s: %d risks", method, len(methodRisks))
		}
	})
}
