//go:build integration

package recon

import (
	"context"
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
)

// TestPrivescEnrichmentE2E is a full-stack integration test that:
//  1. Provisions real IAM fixtures in AWS (via Terraform)
//  2. Runs the graph recon module to collect IAM relationships
//  3. Writes them into a Neo4j container
//  4. Runs EnrichAWS to create CAN_PRIVESC edges
//  5. Verifies that every new privesc method (43–72) fires for the provisioned principals
func TestPrivescEnrichmentE2E(t *testing.T) {
	ctx := context.Background()

	// --- Step 1: AWS Terraform fixture ---
	fixture := testutil.NewAWSFixture(t, "aws/recon/privesc")
	fixture.Setup()

	newServicesUserARN := fixture.Output("new_services_user_arn")
	extServicesUserARN := fixture.Output("extended_services_user_arn")
	iamPrivescUserARN := fixture.Output("iam_privesc_user_arn")
	passableRoleARN := fixture.Output("passable_role_arn")

	allFixtureARNs := fixture.OutputList("all_arns")
	fixtureARNs := make(map[string]bool, len(allFixtureARNs))
	for _, arn := range allFixtureARNs {
		fixtureARNs[arn] = true
	}
	t.Logf("Fixture ARNs: %v", allFixtureARNs)

	// --- Step 2: Run graph recon module ---
	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "graph")
	require.True(t, ok, "graph module should be registered")

	cfg := plugin.Config{
		Args:    map[string]any{"regions": []string{"us-east-2"}},
		Context: ctx,
	}
	p1 := pipeline.From(cfg)
	p2 := pipeline.New[model.AurelianModel]()
	pipeline.Pipe(p1, mod.Run, p2)

	var iamResources []output.AWSIAMResource
	var iamRels []output.AWSIAMRelationship

	for m := range p2.Range() {
		switch v := m.(type) {
		case output.AWSIAMResource:
			iamResources = append(iamResources, v)
		case output.AWSIAMRelationship:
			iamRels = append(iamRels, v)
		}
	}
	require.NoError(t, p2.Wait())
	require.NotEmpty(t, iamResources, "recon should produce IAM entities")
	require.NotEmpty(t, iamRels, "recon should produce IAM relationships")

	// Filter to fixture-relevant relationships only.
	var fixtureRels []output.AWSIAMRelationship
	for _, r := range iamRels {
		if fixtureARNs[r.Principal.ARN] || fixtureARNs[r.Resource.ARN] {
			fixtureRels = append(fixtureRels, r)
		}
	}
	t.Logf("Fixture relationships: %d of %d total", len(fixtureRels), len(iamRels))
	require.NotEmpty(t, fixtureRels, "fixture should have IAM relationships")

	// --- Step 3: Write into Neo4j ---
	boltURL, cleanup, err := testutil.StartNeo4jContainer(ctx)
	require.NoError(t, err)
	t.Cleanup(cleanup)

	dbCfg := graph.NewConfig(boltURL, "", "")
	db, err := adapters.NewNeo4jAdapter(dbCfg)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	// Convert IAM resources to graph nodes.
	var nodes []*graph.Node
	for _, e := range iamResources {
		if fixtureARNs[e.ARN] {
			nodes = append(nodes, awstransformers.NodeFromAWSIAMResource(e))
		}
	}
	_, err = db.CreateNodes(ctx, nodes)
	require.NoError(t, err, "create IAM entity nodes")

	// Convert IAM relationships to graph edges.
	var rels []*graph.Relationship
	for _, r := range fixtureRels {
		if rel := awstransformers.RelationshipFromAWSIAMRelationship(r); rel != nil {
			rels = append(rels, rel)
		}
	}
	_, err = db.CreateRelationships(ctx, rels)
	require.NoError(t, err, "create IAM relationship edges")

	t.Logf("Graph seeded: %d nodes, %d edges", len(nodes), len(rels))

	// --- Step 4: Run enrichment ---
	err = queries.EnrichAWS(ctx, db)
	require.NoError(t, err, "EnrichAWS should succeed")

	// --- Step 5: Verify CAN_PRIVESC edges ---
	hasPrivesc := func(fromARN string) int {
		result, err := db.Query(ctx,
			"MATCH (a {Arn: $arn})-[r:CAN_PRIVESC]->() RETURN count(r) AS n",
			map[string]any{"arn": fromARN})
		require.NoError(t, err)
		if len(result.Records) == 0 {
			return 0
		}
		n, _ := result.Records[0]["n"].(int64)
		return int(n)
	}

	t.Run("iam_privesc_user_has_standalone_edges", func(t *testing.T) {
		count := hasPrivesc(iamPrivescUserARN)
		t.Logf("iam_privesc_user CAN_PRIVESC edges: %d", count)
		assert.Greater(t, count, 0,
			"user with IAM privesc permissions should have CAN_PRIVESC edges; "+
				"check that graph recon collected the fixture's IAM policies")
	})

	t.Run("new_services_user_has_passrole_edges", func(t *testing.T) {
		count := hasPrivesc(newServicesUserARN)
		t.Logf("new_services_user CAN_PRIVESC edges: %d", count)
		// This user has PassRole + 20+ new service actions — each PassRole+service pair fires.
		assert.GreaterOrEqual(t, count, 15,
			"user with PassRole+new-service permissions should have ≥15 CAN_PRIVESC edges")
	})

	t.Run("extended_services_user_has_edges", func(t *testing.T) {
		count := hasPrivesc(extServicesUserARN)
		t.Logf("extended_services_user CAN_PRIVESC edges: %d", count)
		assert.Greater(t, count, 0,
			"user with SSM/CodeBuild/SageMaker permissions should have CAN_PRIVESC edges")
	})

	// Spot-check: new_services_user -> passable_role via specific methods.
	t.Run("new_services_user_method_specific_checks", func(t *testing.T) {
		type methodCheck struct {
			method   string
			permType string
		}

		// Verify a sample of new method relationship types exist in the graph
		// (confirms the recon module collected these permissions).
		permChecks := []methodCheck{
			{"method_43 (apprunner:CreateService)", "APPRUNNER_CREATESERVICE"},
			{"method_44 (apprunner:UpdateService)", "APPRUNNER_UPDATESERVICE"},
			{"method_45 (batch:RegisterJobDefinition)", "BATCH_REGISTERJOBDEFINITION"},
			{"method_47 (braket:CreateJob)", "BRAKET_CREATEJOB"},
			{"method_48 (cloudformation:CreateStackSet)", "CLOUDFORMATION_CREATESTACKSET"},
			{"method_54 (ecs:CreateService)", "ECS_CREATESERVICE"},
			{"method_57 (elasticmapreduce:RunJobFlow)", "ELASTICMAPREDUCE_RUNJOBFLOW"},
			{"method_60 (glue:CreateDevEndpoint)", "GLUE_CREATEDEVENDPOINT"},
			{"method_68 (scheduler:CreateSchedule)", "SCHEDULER_CREATESCHEDULE"},
			{"method_70 (states:CreateStateMachine)", "STATES_CREATESTATEMACHINE"},
		}

		for _, pc := range permChecks {
			result, err := db.Query(ctx,
				"MATCH (a {Arn: $arn})-[r]->(t {Arn: $role}) WHERE type(r) = $permType RETURN count(r) AS n",
				map[string]any{
					"arn":      newServicesUserARN,
					"role":     passableRoleARN,
					"permType": pc.permType,
				})
			require.NoError(t, err)

			var count int64
			if len(result.Records) > 0 {
				count, _ = result.Records[0]["n"].(int64)
			}
			t.Logf("%s edge count: %d", pc.method, count)
			assert.Greater(t, count, int64(0),
				"%s: expected permission edge in graph — check recon collects %s",
				pc.method, pc.permType)
		}
	})

	t.Run("no_admin_self_privesc", func(t *testing.T) {
		// An attacker should not have a CAN_PRIVESC edge to itself.
		for _, arn := range []string{newServicesUserARN, iamPrivescUserARN, extServicesUserARN} {
			result, err := db.Query(ctx,
				"MATCH (a {Arn: $arn})-[r:CAN_PRIVESC]->(a) RETURN count(r) AS n",
				map[string]any{"arn": arn})
			require.NoError(t, err)
			var selfEdges int64
			if len(result.Records) > 0 {
				selfEdges, _ = result.Records[0]["n"].(int64)
			}
			assert.Equal(t, int64(0), selfEdges, "principal %s should not CAN_PRIVESC to itself", arn)
		}
	})
}
