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

// labTestCase describes one pathfinding.cloud lab scenario.
// Each case asserts that a specific Aurelian privesc method fires (TP)
// or does NOT fire (FP) for the given attacker.
type labTestCase struct {
	// labID is the pathfinding.cloud PLABS ID (key in attacker_arns output).
	labID string
	// methodID is the expected Aurelian enrichment method (e.g. "aws/enrich/privesc/method_01").
	methodID string
	// shouldFire=true means the method must produce ≥1 CAN_PRIVESC edge (TP).
	// shouldFire=false means NO CAN_PRIVESC edge must be produced (FP).
	shouldFire bool
	// description explains what the lab validates.
	description string
}

// pathfindingLabCases is the mapping table from pathfinding.cloud labs
// to Aurelian privesc methods. Add rows here as new labs are enabled.
//
// Lab naming convention mirrors DataDog/pathfinding-labs directory structure:
//   iam-001-iam-createpolicyversion → method_01 (TP)
//   lambda-003-fp → method_39 should NOT fire (missing InvokeFunction) (FP)
var pathfindingLabCases = []labTestCase{
	// ---- IAM self-escalation (TP) ----
	{"iam-001", "aws/enrich/privesc/method_01", true, "iam:CreatePolicyVersion → method_01 fires"},
	{"iam-002", "aws/enrich/privesc/method_03", true, "iam:CreateAccessKey → method_03 fires"},
	{"iam-004", "aws/enrich/privesc/method_04", true, "iam:CreateLoginProfile → method_04 fires"},
	{"iam-006", "aws/enrich/privesc/method_05", true, "iam:UpdateLoginProfile → method_05 fires"},
	{"iam-012", "aws/enrich/privesc/method_13", true, "iam:UpdateAssumeRolePolicy → method_13 fires"},

	// ---- Lambda privesc (TP) ----
	{"lambda-001", "aws/enrich/privesc/method_14", true, "PassRole+CreateFunction+InvokeFunction → method_14 fires"},
	{"lambda-003", "aws/enrich/privesc/method_20", true, "lambda:UpdateFunctionCode alone → method_20 fires"},

	// ---- Lambda false positive (FP) ----
	// method_39 requires BOTH UpdateFunctionCode AND InvokeFunction.
	// lambda-003-fp user has only UpdateFunctionCode → method_39 must NOT fire.
	{"lambda-003-fp", "aws/enrich/privesc/method_39", false, "UpdateFunctionCode alone must NOT trigger method_39 (needs InvokeFunction too)"},

	// ---- Glue privesc (TP) ----
	{"glue-002", "aws/enrich/privesc/method_29", true, "glue:UpdateDevEndpoint → method_29 fires"},
	{"glue-003", "aws/enrich/privesc/method_80", true, "PassRole+CreateJob+StartJobRun → method_80 fires"},

	// ---- EC2 privesc (TP) ----
	{"ec2-001", "aws/enrich/privesc/method_15", true, "PassRole+RunInstances → method_15 fires"},
	{"ec2-003", "aws/enrich/privesc/method_52", true, "ec2-instance-connect:SendSSHPublicKey → method_52 fires"},
	{"ec2-004", "aws/enrich/privesc/method_73", true, "PassRole+RequestSpotInstances → method_73 fires"},
}

// TestPrivescPathfindingCloudE2E is a table-driven full-stack integration test
// that mirrors the pathfinding.cloud lab model: each attacker IAM user holds
// exactly the permissions for one privesc technique, enabling ground-truth
// per-method true-positive and false-positive validation.
//
// Run with: go test -tags integration -run TestPrivescPathfindingCloudE2E ./pkg/modules/aws/recon/...
func TestPrivescPathfindingCloudE2E(t *testing.T) {
	ctx := context.Background()

	// --- Step 1: Deploy pathfinding-style fixture ---
	fixture := testutil.NewAWSFixture(t, "aws/recon/privesc-pathfinding")
	fixture.Setup()

	// Build attacker ARN map from fixture outputs.
	attackerARNs := map[string]string{}
	// The fixture outputs a JSON map under "attacker_arns" — extract each lab.
	for _, labID := range []string{
		"iam-001", "iam-002", "iam-004", "iam-006", "iam-012",
		"lambda-001", "lambda-003", "lambda-003-fp",
		"glue-002", "glue-003",
		"ec2-001", "ec2-003", "ec2-004",
	} {
		attackerARNs[labID] = fixture.Output("attacker_arns." + labID)
	}

	allARNs := fixture.OutputList("all_arns")
	fixtureARNs := make(map[string]bool, len(allARNs))
	for _, arn := range allARNs {
		fixtureARNs[arn] = true
	}

	// --- Step 2: Run graph recon ---
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
	require.NotEmpty(t, iamRels)

	// Filter to fixture-relevant relationships.
	var fixtureRels []output.AWSIAMRelationship
	for _, r := range iamRels {
		if fixtureARNs[r.Principal.ARN] || fixtureARNs[r.Resource.ARN] {
			fixtureRels = append(fixtureRels, r)
		}
	}
	t.Logf("Fixture relationships: %d of %d total", len(fixtureRels), len(iamRels))

	// --- Step 3: Seed Neo4j ---
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

	seen := map[string]bool{}
	var nodes []*graph.Node
	for _, rel := range rels {
		for _, n := range []*graph.Node{rel.StartNode, rel.EndNode} {
			if n == nil || len(n.UniqueKey) == 0 {
				continue
			}
			key := fmt.Sprintf("%v", n.Properties[n.UniqueKey[0]])
			if !seen[key] {
				seen[key] = true
				nodes = append(nodes, n)
			}
		}
	}
	_, err = db.CreateNodes(ctx, nodes)
	require.NoError(t, err)
	_, err = db.CreateRelationships(ctx, rels)
	require.NoError(t, err)

	// Apply Principal label fixup (production schema issue tracked separately).
	_, err = db.Query(ctx, `
		MATCH (n)
		WHERE any(lbl IN labels(n) WHERE lbl IN ['AWS::IAM::User','AWS::IAM::Role','AWS::IAM::Group'])
		  AND n.arn IS NOT NULL
		SET n:Principal, n.Arn = n.arn`, nil)
	require.NoError(t, err)

	// --- Step 4: Run enrichment ---
	err = queries.EnrichAWS(ctx, db)
	require.NoError(t, err)

	// --- Step 5: Table-driven assertions ---
	for _, tc := range pathfindingLabCases {
		tc := tc
		t.Run(fmt.Sprintf("%s/%s", tc.labID, tc.methodID), func(t *testing.T) {
			attackerARN, ok := attackerARNs[tc.labID]
			if !ok || attackerARN == "" {
				t.Skipf("attacker ARN not available for lab %s (fixture output missing)", tc.labID)
				return
			}

			// Count CAN_PRIVESC edges from this attacker where the method property matches.
			result, err := db.Query(ctx,
				`MATCH (a)-[r:CAN_PRIVESC]->()
				 WHERE (a.Arn = $arn OR a.arn = $arn)
				 RETURN count(r) AS n`,
				map[string]any{"arn": attackerARN})
			require.NoError(t, err)

			var count int64
			if len(result.Records) > 0 {
				switch v := result.Records[0]["n"].(type) {
				case int64:
					count = v
				case float64:
					count = int64(v)
				}
			}

			if tc.shouldFire {
				assert.Greater(t, int(count), 0,
					"[TP] lab=%s method=%s: expected ≥1 CAN_PRIVESC edge — %s",
					tc.labID, tc.methodID, tc.description)
			} else {
				assert.Equal(t, int64(0), count,
					"[FP] lab=%s method=%s: expected 0 CAN_PRIVESC edges — %s",
					tc.labID, tc.methodID, tc.description)
			}
		})
	}
}
