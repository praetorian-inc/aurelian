//go:build integration

package analyze

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/graph"
	"github.com/praetorian-inc/aurelian/pkg/graph/adapters"
	"github.com/praetorian-inc/aurelian/pkg/graph/queries"
	awstransformers "github.com/praetorian-inc/aurelian/pkg/graph/transformers/aws"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	// Register the recon `graph` module (step 2 drives plugin.Get(...CategoryRecon,"graph"))
	// and the AWS enrichers used by EnrichAWS. The analyze package's own init() registers the
	// analyze `graph` module, but NOT the recon one, so without this blank import
	// plugin.Get(PlatformAWS, CategoryRecon, "graph") returns false.
	_ "github.com/praetorian-inc/aurelian/pkg/modules/aws/recon"
)

// TestGraphAnalyzePrivescPathsE2E is a full-stack integration test that:
//  1. Provisions real IAM fixtures in AWS (via Terraform)
//  2. Runs the graph recon module to collect IAM relationships
//  3. Writes them into a Neo4j container + runs EnrichAWS
//  4. Drives the `aws analyze graph` module against that graph and asserts it
//     emits AurelianRisk findings for the provisioned privesc paths.
func TestGraphAnalyzePrivescPathsE2E(t *testing.T) {
	ctx := context.Background()

	// --- Step 1: AWS Terraform fixture ---
	fixture := testutil.NewAWSFixture(t, "aws/recon/privesc")
	fixture.Setup()

	newServicesUserARN := fixture.Output("new_services_user_arn")

	allFixtureARNs := fixture.OutputList("all_arns")
	fixtureARNs := make(map[string]bool, len(allFixtureARNs))
	for _, arn := range allFixtureARNs {
		fixtureARNs[arn] = true
	}

	// --- Step 2: Run graph recon module ---
	reconMod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "graph")
	require.True(t, ok, "recon graph module should be registered")

	reconCfg := plugin.Config{
		Args:    map[string]any{"regions": []string{"us-east-2"}},
		Context: ctx,
	}
	rp1 := pipeline.From(reconCfg)
	rp2 := pipeline.New[model.AurelianModel]()
	pipeline.Pipe(rp1, reconMod.Run, rp2)

	var iamRels []output.AWSIAMRelationship
	var iamResources []output.AWSIAMResource
	for m := range rp2.Range() {
		switch v := m.(type) {
		case output.AWSIAMRelationship:
			iamRels = append(iamRels, v)
		case output.AWSIAMResource:
			iamResources = append(iamResources, v)
		}
	}
	require.NoError(t, rp2.Wait())
	require.NotEmpty(t, iamRels, "recon should produce IAM relationships")
	require.NotEmpty(t, iamResources, "recon should produce IAM entities")

	var fixtureRels []output.AWSIAMRelationship
	for _, r := range iamRels {
		if fixtureARNs[r.Principal.ARN] || fixtureARNs[r.Resource.ARN] {
			fixtureRels = append(fixtureRels, r)
		}
	}
	require.NotEmpty(t, fixtureRels, "fixture should have IAM relationships")

	// --- Step 3: Seed Neo4j + enrich ---
	boltURL, cleanup, err := testutil.StartNeo4jContainer(ctx)
	require.NoError(t, err)
	t.Cleanup(cleanup)

	dbCfg := graph.NewConfig(boltURL, "", "")
	db, err := adapters.NewNeo4jAdapter(dbCfg)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	var rels []*graph.Relationship
	for _, r := range fixtureRels {
		if rel := awstransformers.RelationshipFromAWSIAMRelationship(r); rel != nil {
			rels = append(rels, rel)
		}
	}

	// buildRelationshipMergeQuery MATCHes both endpoints, so collect and create
	// every unique node referenced by the relationships before creating edges.
	seen := map[string]bool{}
	var nodes []*graph.Node
	addNode := func(n *graph.Node) {
		if n == nil || len(n.UniqueKey) == 0 {
			return
		}
		key := ""
		for _, k := range n.UniqueKey {
			if v, ok := n.Properties[k]; ok {
				key += k + "=" + fmt.Sprintf("%v", v) + ";"
			}
		}
		if !seen[key] {
			seen[key] = true
			nodes = append(nodes, n)
		}
	}
	// Seed RICH GAAD entity nodes (with OriginalData → AttachedManagedPolicies / trust /
	// etc.) for every fixture-owned IAM resource BEFORE the relationship-endpoint nodes.
	// addNode dedups by UniqueKey, so the rich node wins over the thin {Arn}-only endpoint
	// node that RelationshipFromAWSIAMRelationship would otherwise create. This is required
	// for the analysis path: privesc_paths.yaml filters on target._is_admin, and the
	// set_admin enricher only marks a role _is_admin from its AttachedManagedPolicies (the
	// admin policy ARN), which lives on the rich GAAD node — not on a thin endpoint node.
	// Without this, CAN_PRIVESC edges still form (their guards also accept _is_privileged)
	// but NO admin-target path exists, so the analyze module emits zero risks.
	for _, r := range iamResources {
		if r.ARN != "" && !fixtureARNs[r.ARN] {
			continue // only seed fixture-owned entities to keep the graph bounded
		}
		addNode(awstransformers.NodeFromAWSIAMResource(r))
	}
	for _, rel := range rels {
		addNode(rel.StartNode)
		addNode(rel.EndNode)
	}

	_, err = db.CreateNodes(ctx, nodes)
	require.NoError(t, err, "create all referenced nodes")
	_, err = db.CreateRelationships(ctx, rels)
	require.NoError(t, err, "create IAM relationship edges")

	require.NoError(t, queries.EnrichAWS(ctx, db), "EnrichAWS should succeed")

	// --- Step 4: Drive the analyze graph module against the seeded graph ---
	analyzeMod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryAnalyze, "graph")
	require.True(t, ok, "analyze graph module should be registered")

	runAnalyze := func() []output.AurelianRisk {
		cfg := plugin.Config{
			Args: map[string]any{
				"neo4j-uri":      boltURL,
				"neo4j-username": "",
				"neo4j-password": "",
			},
			Context: ctx,
		}
		p1 := pipeline.From(cfg)
		p2 := pipeline.New[model.AurelianModel]()
		pipeline.Pipe(p1, analyzeMod.Run, p2)

		var risks []output.AurelianRisk
		for m := range p2.Range() {
			if r, ok := m.(output.AurelianRisk); ok {
				risks = append(risks, r)
			}
		}
		require.NoError(t, p2.Wait())
		return risks
	}

	risks := runAnalyze()
	require.NotEmpty(t, risks, "analyze graph should emit at least one privesc-path risk")

	for _, r := range risks {
		assert.Equal(t, "aws-privesc-path", r.Name, "every emitted risk must be a privesc-path finding")
		assert.NotEmpty(t, r.DeduplicationID, "every risk must carry a stable deduplication id")
	}

	// The passable role has AdministratorAccess (_is_admin), so new_services_user
	// must surface as an attacker reaching it via the PassRole+service methods.
	var attackerRisk *output.AurelianRisk
	for i := range risks {
		if risks[i].ImpactedResourceID == newServicesUserARN {
			attackerRisk = &risks[i]
			break
		}
	}
	require.NotNil(t, attackerRisk,
		"new_services_user must appear as the impacted resource of a privesc-path risk")

	assert.Equal(t, output.RiskSeverityHigh, attackerRisk.Severity,
		"a path to an admin target must be rated high")

	var pathCtx struct {
		AttackerARN  string   `json:"attacker_arn"`
		TargetARN    string   `json:"target_arn"`
		Methods      []string `json:"methods"`
		HopCount     int64    `json:"hop_count"`
		PathSeverity string   `json:"path_severity"`
	}
	require.NoError(t, json.Unmarshal(attackerRisk.Context, &pathCtx))
	assert.Equal(t, newServicesUserARN, pathCtx.AttackerARN)
	assert.NotEmpty(t, pathCtx.Methods, "the path context must carry the per-hop methods")
	t.Logf("new_services_user privesc path: %s → %s via %v (%d hops, %s)",
		pathCtx.AttackerARN, pathCtx.TargetARN, pathCtx.Methods, pathCtx.HopCount, pathCtx.PathSeverity)

	// DeduplicationID must be stable across a second run of the same graph.
	risks2 := runAnalyze()
	dedups2 := map[string]bool{}
	for _, r := range risks2 {
		dedups2[r.DeduplicationID] = true
	}
	assert.True(t, dedups2[attackerRisk.DeduplicationID],
		"deduplication id must be stable across repeated analysis runs")
}
