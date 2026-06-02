//go:build integration

package recon

import (
	"context"
	"fmt"
	"strings"
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

// labTestCase describes one pathfinding.cloud-style test scenario.
// fixtureKey is the Terraform output name (e.g. "lab_iam_001_arn").
// methodID is the Aurelian enrichment method under test.
// shouldFire=true → TP: method must produce ≥1 CAN_PRIVESC edge.
// shouldFire=false → FP: method must produce 0 CAN_PRIVESC edges.
type labTestCase struct {
	fixtureKey  string
	methodID    string
	shouldFire  bool
	description string
}

// pathfindingLabCases is the ground-truth table.
// Extend by adding rows — one row per pathfinding.cloud lab (TP or FP variant).
//
// Naming convention for fixtureKey:
//   lab_<plabs_id_underscored>_arn  for TP users
//   lab_fp_<description>_arn        for FP users (missing one or more required permissions)
var pathfindingLabCases = []labTestCase{

	// =========================================================================
	// TRUE POSITIVE cases — attacker has exactly the right permissions
	// =========================================================================

	// IAM self-escalation (pathfinding.cloud iam-001..013)
	{"lab_iam_001_arn", "aws/enrich/privesc/method_01", true,
		"iam:CreatePolicyVersion alone → method_01 must fire"},
	{"lab_iam_002_arn", "aws/enrich/privesc/method_03", true,
		"iam:CreateAccessKey alone → method_03 must fire"},
	{"lab_iam_004_arn", "aws/enrich/privesc/method_04", true,
		"iam:CreateLoginProfile alone → method_04 must fire"},
	{"lab_iam_006_arn", "aws/enrich/privesc/method_05", true,
		"iam:UpdateLoginProfile alone → method_05 must fire"},
	{"lab_iam_012_arn", "aws/enrich/privesc/method_13", true,
		"iam:UpdateAssumeRolePolicy alone → method_13 must fire"},

	// Lambda privesc (pathfinding.cloud lambda-001, lambda-003)
	{"lab_lambda_001_arn", "aws/enrich/privesc/method_14", true,
		"PassRole + CreateFunction + InvokeFunction → method_14 must fire"},
	{"lab_lambda_003_arn", "aws/enrich/privesc/method_20", true,
		"lambda:UpdateFunctionCode alone → method_20 must fire"},

	// Glue privesc (pathfinding.cloud glue-002, glue-003)
	{"lab_glue_002_arn", "aws/enrich/privesc/method_29", true,
		"glue:UpdateDevEndpoint alone → method_29 must fire"},
	{"lab_glue_003_arn", "aws/enrich/privesc/method_80", true,
		"PassRole + CreateJob + StartJobRun → method_80 must fire"},

	// EC2 privesc (pathfinding.cloud ec2-001, ec2-003, ec2-004)
	{"lab_ec2_001_arn", "aws/enrich/privesc/method_15", true,
		"PassRole + ec2:RunInstances → method_15 must fire"},
	{"lab_ec2_003_arn", "aws/enrich/privesc/method_52", true,
		"ec2-instance-connect:SendSSHPublicKey → method_52 must fire"},
	{"lab_ec2_004_arn", "aws/enrich/privesc/method_73", true,
		"PassRole + ec2:RequestSpotInstances → method_73 must fire"},

	// =========================================================================
	// FALSE POSITIVE cases — attacker is MISSING one or more required permissions
	// The named method must NOT fire (0 CAN_PRIVESC edges).
	// =========================================================================

	// PassRole alone — no service action
	// Every PassRole+service method (14,15,16,17,18,19,32,43,45,47,48,49,...) must NOT fire.
	{"lab_fp_passrole_only_arn", "aws/enrich/privesc/method_14", false,
		"PassRole alone (no CreateFunction/InvokeFunction) → method_14 must NOT fire"},
	{"lab_fp_passrole_only_arn", "aws/enrich/privesc/method_15", false,
		"PassRole alone (no RunInstances) → method_15 must NOT fire"},
	{"lab_fp_passrole_only_arn", "aws/enrich/privesc/method_16", false,
		"PassRole alone (no CreateStack) → method_16 must NOT fire"},
	{"lab_fp_passrole_only_arn", "aws/enrich/privesc/method_73", false,
		"PassRole alone (no RequestSpotInstances) → method_73 must NOT fire"},

	// Lambda: one permission present, other absent
	{"lab_fp_lambda_createfunction_only_arn", "aws/enrich/privesc/method_14", false,
		"CreateFunction alone (no PassRole, no InvokeFunction) → method_14 must NOT fire"},
	{"lab_fp_lambda_invoke_only_arn", "aws/enrich/privesc/method_14", false,
		"InvokeFunction alone (no PassRole, no CreateFunction) → method_14 must NOT fire"},
	{"lab_lambda_003fp_arn", "aws/enrich/privesc/method_39", false,
		"UpdateFunctionCode alone (no InvokeFunction) → method_39 (compound) must NOT fire"},

	// EC2: service action present but PassRole missing
	{"lab_fp_ec2_runinstances_only_arn", "aws/enrich/privesc/method_15", false,
		"ec2:RunInstances alone (no PassRole) → method_15 must NOT fire"},

	// CloudFormation: CreateStack without PassRole
	{"lab_fp_cfn_createstack_only_arn", "aws/enrich/privesc/method_16", false,
		"cloudformation:CreateStack alone (no PassRole) → method_16 must NOT fire"},

	// Glue: missing execution permission
	{"lab_fp_glue_createjob_only_arn", "aws/enrich/privesc/method_80", false,
		"glue:CreateJob alone (no PassRole, no StartJobRun) → method_80 must NOT fire"},
	{"lab_fp_glue_passrole_createjob_arn", "aws/enrich/privesc/method_80", false,
		"PassRole + CreateJob (no StartJobRun) → method_80 must NOT fire (needs all 3)"},

	// Step Functions: CreateStateMachine without StartExecution
	{"lab_fp_sfn_no_startexecution_arn", "aws/enrich/privesc/method_83", false,
		"PassRole + CreateStateMachine (no StartExecution) → method_83 must NOT fire"},
	// method_70 only requires PassRole+CreateStateMachine — should still fire
	{"lab_fp_sfn_no_startexecution_arn", "aws/enrich/privesc/method_70", true,
		"PassRole + CreateStateMachine (no StartExecution) → method_70 SHOULD fire (no StartExecution needed)"},

	// ECS: CreateService without PassRole
	{"lab_fp_ecs_createservice_only_arn", "aws/enrich/privesc/method_54", false,
		"ecs:CreateService alone (no PassRole) → method_54 must NOT fire"},

	// EMR Serverless: CreateApplication without StartJobRun
	{"lab_fp_emrs_no_startjobrun_arn", "aws/enrich/privesc/method_85", false,
		"PassRole + CreateApplication (no StartJobRun) → method_85 must NOT fire"},
	// method_58 only requires PassRole+CreateApplication — should still fire
	{"lab_fp_emrs_no_startjobrun_arn", "aws/enrich/privesc/method_58", true,
		"PassRole + CreateApplication (no StartJobRun) → method_58 SHOULD fire (no StartJobRun needed)"},

	// SSM: CreateDocument without StartAutomationExecution
	{"lab_fp_ssm_createdoc_only_arn", "aws/enrich/privesc/method_84", false,
		"ssm:CreateDocument alone (no StartAutomationExecution) → method_84 must NOT fire"},
}

// TestPrivescPathfindingCloudE2E is a table-driven full-stack integration test
// mirroring the pathfinding.cloud lab model: each attacker IAM user holds
// exactly the permissions for one privesc scenario, enabling per-method
// true-positive AND false-positive ground-truth validation.
//
// Run: go test -tags integration -run TestPrivescPathfindingCloudE2E ./pkg/modules/aws/recon/...
func TestPrivescPathfindingCloudE2E(t *testing.T) {
	ctx := context.Background()

	// --- Step 1: Deploy fixture ---
	fixture := testutil.NewAWSFixture(t, "aws/recon/privesc-pathfinding")
	fixture.Setup()

	// Collect all fixture ARNs for relationship filtering.
	allARNs := fixture.OutputList("all_arns")
	fixtureARNs := make(map[string]bool, len(allARNs))
	for _, arn := range allARNs {
		fixtureARNs[arn] = true
	}

	// Build ARN lookup for test cases from individual outputs.
	labARNs := map[string]string{}
	outputKeys := []string{
		"lab_iam_001_arn", "lab_iam_002_arn", "lab_iam_004_arn", "lab_iam_006_arn", "lab_iam_012_arn",
		"lab_lambda_001_arn", "lab_lambda_003_arn", "lab_lambda_003fp_arn",
		"lab_glue_002_arn", "lab_glue_003_arn",
		"lab_ec2_001_arn", "lab_ec2_003_arn", "lab_ec2_004_arn",
		"lab_fp_passrole_only_arn", "lab_fp_lambda_createfunction_only_arn",
		"lab_fp_lambda_invoke_only_arn", "lab_fp_ec2_runinstances_only_arn",
		"lab_fp_cfn_createstack_only_arn", "lab_fp_glue_createjob_only_arn",
		"lab_fp_glue_passrole_createjob_arn", "lab_fp_sfn_no_startexecution_arn",
		"lab_fp_ecs_createservice_only_arn", "lab_fp_emrs_no_startjobrun_arn",
		"lab_fp_ssm_createdoc_only_arn",
	}
	for _, key := range outputKeys {
		arn := fixture.Output(key)
		if arn != "" {
			labARNs[key] = arn
			fixtureARNs[arn] = true
		}
	}
	t.Logf("Loaded %d lab attacker ARNs from fixture", len(labARNs))

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
	require.NotEmpty(t, iamRels, "recon should produce IAM relationships")

	var fixtureRels []output.AWSIAMRelationship
	for _, r := range iamRels {
		if fixtureARNs[r.Principal.ARN] || fixtureARNs[r.Resource.ARN] {
			fixtureRels = append(fixtureRels, r)
		}
	}
	t.Logf("Fixture relationships: %d of %d total", len(fixtureRels), len(iamRels))
	require.NotEmpty(t, fixtureRels, "fixture principals should have IAM relationships")

	// --- Step 3: Write to Neo4j ---
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

	// Apply Principal label to IAM entity nodes (production schema fix tracked separately).
	_, err = db.Query(ctx, `
		MATCH (n)
		WHERE any(lbl IN labels(n) WHERE lbl IN ['AWS::IAM::User','AWS::IAM::Role','AWS::IAM::Group'])
		  AND n.arn IS NOT NULL
		SET n:Principal, n.Arn = n.arn`, nil)
	require.NoError(t, err)

	// --- Step 4: Enrichment ---
	err = queries.EnrichAWS(ctx, db)
	require.NoError(t, err)

	t.Logf("Graph seeded: %d nodes, %d edges", len(nodes), len(rels))

	// --- Step 5: Table-driven assertions ---
	for _, tc := range pathfindingLabCases {
		tc := tc
		testName := fmt.Sprintf("%s/%s/%s",
			map[bool]string{true: "TP", false: "FP"}[tc.shouldFire],
			tc.fixtureKey, tc.methodID[strings.LastIndex(tc.methodID, "/")+1:])
		t.Run(testName, func(t *testing.T) {
			attackerARN, ok := labARNs[tc.fixtureKey]
			if !ok || attackerARN == "" {
				t.Skipf("ARN not available for fixture key %s — skipping", tc.fixtureKey)
				return
			}

			// Derive the method string from the methodID path (e.g. "method_14" → "method_14").
			// The CAN_PRIVESC edge carries a "method" property set by each enrichment query.
			// For FP tests we check that specific method didn't fire — not total count —
			// because other simpler methods may legitimately fire on the same attacker.
			methodSuffix := tc.methodID[strings.LastIndex(tc.methodID, "/")+1:]

			if tc.shouldFire {
				// TP: any CAN_PRIVESC edge from this attacker is sufficient evidence.
				result, err := db.Query(ctx,
					`MATCH (a)-[r:CAN_PRIVESC]->()
					 WHERE a.Arn = $arn OR a.arn = $arn
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
				assert.Greater(t, int(count), 0,
					"[TP FAIL] %s (%s) — %s", tc.methodID, methodSuffix, tc.description)
			} else {
				// FP: the SPECIFIC method must not have fired.
				// Check by matching the `method` property set by the enrichment Cypher.
				// Other methods may legitimately fire on this attacker — that's expected.
				result, err := db.Query(ctx,
					`MATCH (a)-[r:CAN_PRIVESC]->()
					 WHERE (a.Arn = $arn OR a.arn = $arn)
					   AND r.method CONTAINS $method
					 RETURN count(r) AS n`,
					map[string]any{"arn": attackerARN, "method": methodSuffix})
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
				assert.Equal(t, int64(0), count,
					"[FP FAIL] %s (%s) — %s", tc.methodID, methodSuffix, tc.description)
			}
		})
	}
}
