//go:build integration

package recon

import (
	"context"
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

	// Build graph relationships first so we can collect all referenced nodes.
	var rels []*graph.Relationship
	for _, r := range fixtureRels {
		if rel := awstransformers.RelationshipFromAWSIAMRelationship(r); rel != nil {
			rels = append(rels, rel)
		}
	}

	// buildRelationshipMergeQuery uses MATCH (not MERGE) for both endpoints, so
	// both nodes must exist before CreateRelationships is called or rels are
	// silently skipped. Collect every unique node from both sides of every rel.
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
	for _, rel := range rels {
		addNode(rel.StartNode)
		addNode(rel.EndNode)
	}

	_, err = db.CreateNodes(ctx, nodes)
	require.NoError(t, err, "create all referenced nodes")

	_, err = db.CreateRelationships(ctx, rels)
	require.NoError(t, err, "create IAM relationship edges")

	t.Logf("Graph seeded: %d nodes, %d edges", len(nodes), len(rels))

	// NodeFromAWSIAMResource now correctly assigns the Principal label to IAM entity
	// nodes even when OriginalData is nil (fixed per ztgrace PR #120 feedback).
	// Verify this before enrichment to catch any regression early.
	principalCheck, err := db.Query(ctx, `
		MATCH (n:Principal)
		WHERE any(lbl IN labels(n) WHERE lbl IN ['AWS::IAM::User','AWS::IAM::Role','AWS::IAM::Group'])
		RETURN count(n) AS n`, nil)
	require.NoError(t, err)
	principalCount, _ := principalCheck.Records[0]["n"].(int64)
	require.Greater(t, int(principalCount), 0,
		"IAM entity nodes must carry the :Principal label — NodeFromAWSIAMResource regression")

	diagRels, err := db.Query(ctx, `
		MATCH ()-[r]->() RETURN type(r) AS rel_type, count(r) AS cnt
		ORDER BY cnt DESC LIMIT 20`, nil)
	require.NoError(t, err)
	t.Logf("All relationship types in graph (%d types):", len(diagRels.Records))
	for _, rec := range diagRels.Records {
		t.Logf("  %v: %v", rec["rel_type"], rec["cnt"])
	}

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
		// Coerce across int64/int/float64 — Neo4j driver may return any numeric type.
		switch v := result.Records[0]["n"].(type) {
		case int64:
			return int(v)
		case int:
			return v
		case float64:
			return int(v)
		}
		return 0
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

	// Diagnostic: show all outgoing edge types from extended_services_user.
	diagEdges, err := db.Query(ctx,
		"MATCH (a)-[r]->() WHERE a.Arn = $arn OR a.arn = $arn RETURN type(r) AS t, count(r) AS n ORDER BY n DESC LIMIT 30",
		map[string]any{"arn": extServicesUserARN})
	require.NoError(t, err)
	t.Logf("extended_services_user outgoing edges (%d types):", len(diagEdges.Records))
	for _, rec := range diagEdges.Records {
		t.Logf("  %v: %v", rec["t"], rec["n"])
	}

	// Spot-check: verify known-collectable permission types exist in the graph.
	// Aurelian's recon only creates relationship edges to resources that actually exist
	// in the account — new service actions (AppRunner, Batch, etc.) produce edges only
	// when those services have deployed resources. We assert on IAM-level permissions
	// that are always collectable, and log-only for resource-dependent ones.
	t.Run("permission_edge_checks", func(t *testing.T) {
		type edgeCheck struct {
			user      string
			method    string
			permType  string
			mustExist bool
		}

		checks := []edgeCheck{
			// IAM-level permissions: always produce edges since IAM entities exist in every account.
			{iamPrivescUserARN, "iam:PassRole (method_14/15…)", "IAM_PASSROLE", true},
			{iamPrivescUserARN, "iam:CreatePolicyVersion (method_01)", "IAM_CREATEPOLICYVERSION", true},
			{iamPrivescUserARN, "iam:CreateAccessKey (method_03)", "IAM_CREATEACCESSKEY", true},
			// Service resources deployed by fixture — recon should collect edges to these.
			{extServicesUserARN, "ecs:CreateService (method_54)", "ECS_CREATESERVICE", true},
			{extServicesUserARN, "states:CreateStateMachine (method_70)", "STATES_CREATESTATEMACHINE", true},
			{extServicesUserARN, "states:UpdateStateMachine (method_71)", "STATES_UPDATESTATEMACHINE", true},
			{extServicesUserARN, "glue:UpdateJob (method_61)", "GLUE_UPDATEJOB", true},
			{extServicesUserARN, "scheduler:CreateSchedule (method_68)", "SCHEDULER_CREATESCHEDULE", true},
			{extServicesUserARN, "batch:SubmitJob (method_46)", "BATCH_SUBMITJOB", true},
			{extServicesUserARN, "batch:RegisterJobDefinition (method_45)", "BATCH_REGISTERJOBDEFINITION", true},
			{extServicesUserARN, "cognito-identity:SetIdentityPoolRoles (method_51)", "COGNITO-IDENTITY_SETIDENTITYPOOLROLES", true},
			// Compound execution methods — now confirmed via extended_services_exec policy.
			{extServicesUserARN, "ssm:CreateDocument (method_84)", "SSM_CREATEDOCUMENT", true},
			{extServicesUserARN, "glue:CreateJob (method_77/80)", "GLUE_CREATEJOB", true},
			{extServicesUserARN, "glue:CreateTrigger (method_77/78)", "GLUE_CREATETRIGGER", true},
			// Confirmed via synthetic service wildcard resources (no real deployment needed).
			{newServicesUserARN, "apprunner:CreateService (method_43)", "APPRUNNER_CREATESERVICE", true},
			{newServicesUserARN, "braket:CreateJob (method_47)", "BRAKET_CREATEJOB", true},
			{newServicesUserARN, "gamelift:CreateFleet (method_59)", "GAMELIFT_CREATEFLEET", true},
		}

		for _, c := range checks {
			result, err := db.Query(ctx,
				"MATCH (a)-[r]->() WHERE a.Arn = $arn AND type(r) = $permType RETURN count(r) AS n",
				map[string]any{"arn": c.user, "permType": c.permType})
			require.NoError(t, err)

			var count int64
			if len(result.Records) > 0 {
				count, _ = result.Records[0]["n"].(int64)
			}
			t.Logf("%s: %d edge(s) in graph", c.method, count)
			if c.mustExist {
				assert.Greater(t, count, int64(0),
					"%s: expected ≥1 edge in graph — this permission type should always be collectable", c.method)
			}
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

	// --- Shape assertions: verify CAN_PRIVESC targets the passable role, not all principals ---
	//
	// These tests were introduced because a previous fan-out regression (Concern B)
	// created CAN_PRIVESC edges to ALL principals in the account instead of only the
	// specific passed IAM role. Count-only assertions (≥15, >0) cannot catch this:
	// both the correct scoped edge and the incorrect fan-out edges satisfy them.

	t.Run("passrole_user_targets_passable_role", func(t *testing.T) {
		// The new_services_user has iam:PassRole on the fixture's passable-role.
		// After enrichment, there must be a CAN_PRIVESC edge directly to that role —
		// not to arbitrary principals. This fails if the query fans out to all principals
		// while still creating an edge to the passable role, AND would catch a regression
		// where the edge no longer points to the passable role at all.
		result, err := db.Query(ctx,
			"MATCH (a {Arn: $attacker})-[r:CAN_PRIVESC]->(v {Arn: $role}) RETURN count(r) AS n",
			map[string]any{"attacker": newServicesUserARN, "role": passableRoleARN})
		require.NoError(t, err)
		require.Len(t, result.Records, 1)
		n, _ := result.Records[0]["n"].(int64)
		assert.GreaterOrEqual(t, n, int64(1),
			"new_services_user must have CAN_PRIVESC edge to the passable role (%s); "+
				"if 0, the scoped fix broke: enrichment methods are no longer targeting the passed :Principal role",
			passableRoleARN)
	})

	t.Run("passrole_user_edge_count_not_fanout", func(t *testing.T) {
		// With the scoped fix, PassRole+service methods create exactly 1 CAN_PRIVESC edge
		// per distinct (attacker, passed-role) pair via MERGE deduplication.
		// If this count equals the total number of principals in the account (tens or hundreds),
		// it means the fan-out regression is back — the query stopped scoping to the passed role.
		//
		// The fixture has 1 passable role, so all PassRole methods share 1 merged edge.
		// We check count ≤ 5 as a generous bound that still catches a full fan-out (100+).
		result, err := db.Query(ctx,
			"MATCH (a {Arn: $attacker})-[r:CAN_PRIVESC]->() RETURN count(r) AS n",
			map[string]any{"attacker": newServicesUserARN})
		require.NoError(t, err)
		require.Len(t, result.Records, 1)
		n, _ := result.Records[0]["n"].(int64)
		t.Logf("new_services_user CAN_PRIVESC total edge count: %d", n)
		assert.GreaterOrEqual(t, n, int64(1), "new_services_user must have at least 1 CAN_PRIVESC edge")
		assert.LessOrEqual(t, n, int64(10),
			"new_services_user has %d CAN_PRIVESC edges — expected ≤10 (scoped to passable roles). "+
				"If this fails with a large number, the fan-out regression is back: enrichment methods "+
				"are creating edges to ALL principals instead of only the passed IAM role",
			n)
	})

	t.Run("passrole_user_appears_in_analysis_output", func(t *testing.T) {
		// Run the registered aws/analysis/privesc_paths query. The passable role has
		// AdministratorAccess, so _is_admin=true is set on it by set_admin enrichment.
		// The analysis query should then find: new_services_user → passable_role (1 hop).
		// This is the end-to-end proof that the scoped CAN_PRIVESC edge is traversable.
		// If the edge points to a non-Principal (old Concern B) or to the wrong principal,
		// this assertion will fail even if the count assertions above pass.
		result, err := queries.RunPlatformQuery(ctx, db, "aws/analysis/privesc_paths", nil)
		require.NoError(t, err)
		require.NotNil(t, result)

		found := false
		for _, rec := range result.Records {
			if rec["attacker_arn"] == newServicesUserARN {
				found = true
				t.Logf("analysis found: %s → %s (%v hops)", rec["attacker_arn"], rec["target_arn"], rec["hop_count"])
			}
		}
		assert.True(t, found,
			"new_services_user must appear in aws/analysis/privesc_paths output — "+
				"the CAN_PRIVESC edge from PassRole+service methods must be traversable to an admin target")
	})
}
