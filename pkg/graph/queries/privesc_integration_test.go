//go:build integration

package queries

import (
	"context"
	"fmt"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/graph"
	"github.com/praetorian-inc/aurelian/pkg/graph/adapters"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	attackerARN = "arn:aws:iam::123456789012:user/attacker"
	victimARN   = "arn:aws:iam::123456789012:user/victim"
	roleARN     = "arn:aws:iam::123456789012:role/target-role"
	svcResourceARN = "arn:aws:lambda:us-east-1:123456789012:function:test"
)

// privescTestCase describes one enrichment query scenario.
type privescTestCase struct {
	// queryID is the enrichment query to execute (e.g. "aws/enrich/privesc/method_43").
	queryID string
	// setup is Cypher that seeds the graph before the query runs.
	setup string
	// verify returns the count of CAN_PRIVESC edges that should exist after the query.
	verify string
	// wantEdges is the minimum number of expected CAN_PRIVESC edges.
	wantEdges int
}

// standaloneCase builds a test case for single-permission escalation methods.
// The attacker holds permType on any target node; the query should create CAN_PRIVESC to the victim.
func standaloneCase(queryID, permType string) privescTestCase {
	return privescTestCase{
		queryID: queryID,
		setup: fmt.Sprintf(`
			CREATE (a:Principal {Arn: '%s'})
			CREATE (v:Principal {Arn: '%s'})
			CREATE (t:Resource  {Arn: '%s'})
			WITH a, t
			MERGE (a)-[:`+"`%s`"+`]->(t)
		`, attackerARN, victimARN, roleARN, permType),
		verify:    fmt.Sprintf(`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(v {Arn: '%s'}) RETURN count(r) AS n`, attackerARN, victimARN),
		wantEdges: 1,
	}
}

// passRoleCase builds a test case for iam:PassRole + service action escalation methods.
// The attacker holds IAM_PASSROLE on a role and svcPermType on a service resource;
// the query should create CAN_PRIVESC from attacker to the service resource.
func passRoleCase(queryID, svcPermType string) privescTestCase {
	return privescTestCase{
		queryID: queryID,
		setup: fmt.Sprintf(`
			CREATE (a:Principal {Arn: '%s'})
			CREATE (r:Resource  {Arn: '%s'})
			CREATE (s:Resource  {Arn: '%s'})
			WITH a, r, s
			MERGE (a)-[:IAM_PASSROLE]->(r)
			MERGE (a)-[:`+"`%s`"+`]->(s)
		`, attackerARN, roleARN, svcResourceARN, svcPermType),
		verify:    fmt.Sprintf(`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(s {Arn: '%s'}) RETURN count(r) AS n`, attackerARN, svcResourceARN),
		wantEdges: 1,
	}
}

// newPrivescCases returns test cases for all 30 new privesc methods (43–72).
func newPrivescCases() []privescTestCase {
	return []privescTestCase{
		// method_43: iam:PassRole + apprunner:CreateService
		passRoleCase("aws/enrich/privesc/method_43", "APPRUNNER_CREATESERVICE"),

		// method_44: apprunner:UpdateService (standalone — no PassRole required)
		standaloneCase("aws/enrich/privesc/method_44", "APPRUNNER_UPDATESERVICE"),

		// method_45: iam:PassRole + batch:RegisterJobDefinition
		passRoleCase("aws/enrich/privesc/method_45", "BATCH_REGISTERJOBDEFINITION"),

		// method_46: batch:SubmitJob (standalone)
		standaloneCase("aws/enrich/privesc/method_46", "BATCH_SUBMITJOB"),

		// method_47: iam:PassRole + braket:CreateJob
		passRoleCase("aws/enrich/privesc/method_47", "BRAKET_CREATEJOB"),

		// method_48: iam:PassRole + cloudformation:CreateStackSet
		passRoleCase("aws/enrich/privesc/method_48", "CLOUDFORMATION_CREATESTACKSET"),

		// method_49: iam:PassRole + cloudformation:UpdateStackSet
		passRoleCase("aws/enrich/privesc/method_49", "CLOUDFORMATION_UPDATESTACKSET"),

		// method_50: codedeploy:CreateDeployment (standalone)
		standaloneCase("aws/enrich/privesc/method_50", "CODEDEPLOY_CREATEDEPLOYMENT"),

		// method_51: iam:PassRole + cognito-identity:SetIdentityPoolRoles
		passRoleCase("aws/enrich/privesc/method_51", "COGNITO-IDENTITY_SETIDENTITYPOOLROLES"),

		// method_52: ec2-instance-connect:SendSSHPublicKey (standalone)
		standaloneCase("aws/enrich/privesc/method_52", "EC2-INSTANCE-CONNECT_SENDSSHPUBLICKEY"),

		// method_53: ec2:ReplaceIamInstanceProfileAssociation (standalone)
		standaloneCase("aws/enrich/privesc/method_53", "EC2_REPLACEIAMINSTANCEPROFILEASSOCIATION"),

		// method_54: iam:PassRole + ecs:CreateService
		passRoleCase("aws/enrich/privesc/method_54", "ECS_CREATESERVICE"),

		// method_55: iam:PassRole + ecs:StartTask
		passRoleCase("aws/enrich/privesc/method_55", "ECS_STARTTASK"),

		// method_56: ecs:ExecuteCommand (standalone)
		standaloneCase("aws/enrich/privesc/method_56", "ECS_EXECUTECOMMAND"),

		// method_57: iam:PassRole + elasticmapreduce:RunJobFlow
		passRoleCase("aws/enrich/privesc/method_57", "ELASTICMAPREDUCE_RUNJOBFLOW"),

		// method_58: iam:PassRole + emr-serverless:CreateApplication
		passRoleCase("aws/enrich/privesc/method_58", "EMR-SERVERLESS_CREATEAPPLICATION"),

		// method_59: iam:PassRole + gamelift:CreateFleet
		passRoleCase("aws/enrich/privesc/method_59", "GAMELIFT_CREATEFLEET"),

		// method_60: iam:PassRole + glue:CreateDevEndpoint
		passRoleCase("aws/enrich/privesc/method_60", "GLUE_CREATEDEVENDPOINT"),

		// method_61: iam:PassRole + glue:UpdateJob
		passRoleCase("aws/enrich/privesc/method_61", "GLUE_UPDATEJOB"),

		// method_62: iam:PassRole + glue:CreateSession
		passRoleCase("aws/enrich/privesc/method_62", "GLUE_CREATESESSION"),

		// method_63: iam:PassRole + imagebuilder:CreateInfrastructureConfiguration
		passRoleCase("aws/enrich/privesc/method_63", "IMAGEBUILDER_CREATEINFRASTRUCTURECONFIGURATION"),

		// method_64: iam:PassRole + kinesisanalytics:CreateApplication
		passRoleCase("aws/enrich/privesc/method_64", "KINESISANALYTICS_CREATEAPPLICATION"),

		// method_65: lambda:UpdateFunctionCode + lambda:AddPermission (two-perm compound)
		{
			queryID: "aws/enrich/privesc/method_65",
			setup: fmt.Sprintf(`
				CREATE (a:Principal {Arn: '%s'})
				CREATE (v:Principal {Arn: '%s'})
				CREATE (f:Resource  {Arn: '%s'})
				WITH a, v, f
				MERGE (a)-[:LAMBDA_UPDATEFUNCTIONCODE]->(f)
				MERGE (a)-[:LAMBDA_ADDPERMISSION]->(f)
			`, attackerARN, victimARN, svcResourceARN),
			verify:    fmt.Sprintf(`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(v {Arn: '%s'}) RETURN count(r) AS n`, attackerARN, victimARN),
			wantEdges: 1,
		},

		// method_66: iam:PassRole + omics:CreateWorkflow
		passRoleCase("aws/enrich/privesc/method_66", "OMICS_CREATEWORKFLOW"),

		// method_67: sagemaker:UpdateNotebookInstanceLifecycleConfig (standalone)
		standaloneCase("aws/enrich/privesc/method_67", "SAGEMAKER_UPDATENOTEBOOKINSTANCELIFECYCLECONFIG"),

		// method_68: iam:PassRole + scheduler:CreateSchedule
		passRoleCase("aws/enrich/privesc/method_68", "SCHEDULER_CREATESCHEDULE"),

		// method_69: iam:PassRole + ssm:StartAutomationExecution
		passRoleCase("aws/enrich/privesc/method_69", "SSM_STARTAUTOMATIONEXECUTION"),

		// method_70: iam:PassRole + states:CreateStateMachine
		passRoleCase("aws/enrich/privesc/method_70", "STATES_CREATESTATEMACHINE"),

		// method_71: iam:PassRole + states:UpdateStateMachine
		passRoleCase("aws/enrich/privesc/method_71", "STATES_UPDATESTATEMACHINE"),

		// method_72: bedrock-agentcore:InvokeSession (standalone)
		standaloneCase("aws/enrich/privesc/method_72", "BEDROCK-AGENTCORE_INVOKESESSION"),
	}
}

// existingPrivescCases returns a regression sample of pre-existing methods (01–42).
func existingPrivescCases() []privescTestCase {
	return []privescTestCase{
		standaloneCase("aws/enrich/privesc/method_01", "IAM_CREATEPOLICYVERSION"),
		standaloneCase("aws/enrich/privesc/method_02", "IAM_SETDEFAULTPOLICYVERSION"),
		standaloneCase("aws/enrich/privesc/method_03", "IAM_CREATEACCESSKEY"),
		standaloneCase("aws/enrich/privesc/method_04", "IAM_CREATELOGINPROFILE"),
		standaloneCase("aws/enrich/privesc/method_05", "IAM_UPDATELOGINPROFILE"),
		standaloneCase("aws/enrich/privesc/method_06", "IAM_ATTACHUSERPOLICY"),
		standaloneCase("aws/enrich/privesc/method_07", "IAM_ATTACHGROUPPOLICY"),
		standaloneCase("aws/enrich/privesc/method_08", "IAM_ATTACHROLEPOLICY"),
		standaloneCase("aws/enrich/privesc/method_09", "IAM_PUTUSERPOLICY"),
		standaloneCase("aws/enrich/privesc/method_10", "IAM_PUTGROUPPOLICY"),
		standaloneCase("aws/enrich/privesc/method_11", "IAM_PUTROLEPOLICY"),
		standaloneCase("aws/enrich/privesc/method_12", "IAM_ADDUSERTOGROUP"),
		standaloneCase("aws/enrich/privesc/method_13", "IAM_UPDATEASSUMEROLEPOLICY"),
		passRoleCase("aws/enrich/privesc/method_14", "LAMBDA_CREATEFUNCTION"),
		passRoleCase("aws/enrich/privesc/method_15", "EC2_RUNINSTANCES"),
		passRoleCase("aws/enrich/privesc/method_16", "CLOUDFORMATION_CREATESTACK"),
		passRoleCase("aws/enrich/privesc/method_17", "DATAPIPELINE_CREATEPIPELINE"),
		passRoleCase("aws/enrich/privesc/method_18", "GLUE_CREATEJOB"),
		passRoleCase("aws/enrich/privesc/method_19", "SAGEMAKER_CREATENOTEBOOKINSTANCE"),
		standaloneCase("aws/enrich/privesc/method_20", "LAMBDA_UPDATEFUNCTIONCODE"),
		standaloneCase("aws/enrich/privesc/method_21", "LAMBDA_CREATEEVENTSOURCEMAPPING"),
		standaloneCase("aws/enrich/privesc/method_22", "STS_ASSUMEROLE"),
		standaloneCase("aws/enrich/privesc/method_23", "SSM_SENDCOMMAND"),
		standaloneCase("aws/enrich/privesc/method_24", "SSM_STARTSESSION"),
		standaloneCase("aws/enrich/privesc/method_25", "SSM_CREATEASSOCIATION"),
		passRoleCase("aws/enrich/privesc/method_27", "CODEBUILD_CREATEPROJECT"),
		passRoleCase("aws/enrich/privesc/method_30", "CLOUDFORMATION_UPDATESTACK"),
		passRoleCase("aws/enrich/privesc/method_32", "ECS_RUNTASK"),
		standaloneCase("aws/enrich/privesc/method_33", "CODEBUILD_STARTBUILD"),
		passRoleCase("aws/enrich/privesc/method_34", "CODEBUILD_UPDATEPROJECT"),
		standaloneCase("aws/enrich/privesc/method_35", "SAGEMAKER_CREATEPRESIGNEDNOTEBOOKINSTANCEURL"),
		passRoleCase("aws/enrich/privesc/method_36", "SAGEMAKER_CREATETRAININGJOB"),
		passRoleCase("aws/enrich/privesc/method_37", "SAGEMAKER_CREATEPROCESSINGJOB"),
		passRoleCase("aws/enrich/privesc/method_40", "BEDROCK-AGENTCORE_CREATECODEINTERPRETER"),
	}
}

// TestPrivescQueriesNeo4j verifies every privesc enrichment query creates
// CAN_PRIVESC edges when the required IAM permission relationships are present.
// Requires a Neo4j container (testcontainers).
func TestPrivescQueriesNeo4j(t *testing.T) {
	ctx := context.Background()

	boltURL, cleanup, err := testutil.StartNeo4jContainer(ctx)
	require.NoError(t, err, "start Neo4j container")
	t.Cleanup(cleanup)

	newAdapter := func(t *testing.T) graph.GraphDatabase {
		t.Helper()
		cfg := graph.NewConfig(boltURL, "", "")
		adapter, err := adapters.NewNeo4jAdapter(cfg)
		require.NoError(t, err)
		t.Cleanup(func() { adapter.Close() })
		return adapter
	}

	clearDB := func(t *testing.T, db graph.GraphDatabase) {
		t.Helper()
		_, err := db.Query(ctx, "MATCH (n) DETACH DELETE n", nil)
		require.NoError(t, err, "clear graph for test isolation")
	}

	runCase := func(t *testing.T, tc privescTestCase) {
		t.Helper()
		db := newAdapter(t)
		clearDB(t, db)

		_, err := db.Query(ctx, tc.setup, nil)
		require.NoError(t, err, "seed graph for %s", tc.queryID)

		_, err = RunPlatformQuery(ctx, db, tc.queryID, nil)
		require.NoError(t, err, "run enrichment query %s", tc.queryID)

		result, err := db.Query(ctx, tc.verify, nil)
		require.NoError(t, err, "verify CAN_PRIVESC for %s", tc.queryID)

		require.Len(t, result.Records, 1, "verify query should return exactly one row")
		n, ok := result.Records[0]["n"]
		require.True(t, ok, "verify query should return column 'n'")

		count, ok := toInt64(n)
		require.True(t, ok, "count should be numeric, got %T", n)
		assert.GreaterOrEqual(t, int(count), tc.wantEdges,
			"method %s: expected at least %d CAN_PRIVESC edge(s), got %d",
			tc.queryID, tc.wantEdges, count)
	}

	t.Run("new_methods", func(t *testing.T) {
		for _, tc := range newPrivescCases() {
			tc := tc
			t.Run(tc.queryID, func(t *testing.T) {
				runCase(t, tc)
			})
		}
	})

	t.Run("existing_methods_regression", func(t *testing.T) {
		for _, tc := range existingPrivescCases() {
			tc := tc
			t.Run(tc.queryID, func(t *testing.T) {
				runCase(t, tc)
			})
		}
	})
}

// TestEnrichAWSPrivescEndToEnd seeds a graph with all new-method permission
// relationships and verifies that running EnrichAWS creates CAN_PRIVESC edges
// for each new service pathway.
func TestEnrichAWSPrivescEndToEnd(t *testing.T) {
	ctx := context.Background()

	boltURL, cleanup, err := testutil.StartNeo4jContainer(ctx)
	require.NoError(t, err, "start Neo4j container")
	t.Cleanup(cleanup)

	cfg := graph.NewConfig(boltURL, "", "")
	db, err := adapters.NewNeo4jAdapter(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	// Clear and seed the graph with one attacker holding every new-method permission.
	_, err = db.Query(ctx, "MATCH (n) DETACH DELETE n", nil)
	require.NoError(t, err)

	seedCypher := fmt.Sprintf(`
		CREATE (attacker:Principal {Arn: '%s'})
		CREATE (victim:Principal   {Arn: '%s'})
		CREATE (role:Resource      {Arn: '%s'})
		CREATE (svc:Resource       {Arn: '%s'})
		WITH attacker, victim, role, svc

		// PassRole edge (shared prerequisite for all PassRole+service methods)
		MERGE (attacker)-[:IAM_PASSROLE]->(role)

		// New standalone permissions (hyphenated types need backtick escaping in Cypher literals)
		MERGE (attacker)-[:APPRUNNER_UPDATESERVICE]->(svc)
		MERGE (attacker)-[:BATCH_SUBMITJOB]->(svc)
		MERGE (attacker)-[:CODEDEPLOY_CREATEDEPLOYMENT]->(svc)
		MERGE (attacker)-[:`EC2-INSTANCE-CONNECT_SENDSSHPUBLICKEY`]->(svc)
		MERGE (attacker)-[:EC2_REPLACEIAMINSTANCEPROFILEASSOCIATION]->(svc)
		MERGE (attacker)-[:ECS_EXECUTECOMMAND]->(svc)
		MERGE (attacker)-[:SAGEMAKER_UPDATENOTEBOOKINSTANCELIFECYCLECONFIG]->(svc)
		MERGE (attacker)-[:`BEDROCK-AGENTCORE_INVOKESESSION`]->(svc)

		// New PassRole + service permissions
		MERGE (attacker)-[:APPRUNNER_CREATESERVICE]->(svc)
		MERGE (attacker)-[:BATCH_REGISTERJOBDEFINITION]->(svc)
		MERGE (attacker)-[:BRAKET_CREATEJOB]->(svc)
		MERGE (attacker)-[:CLOUDFORMATION_CREATESTACKSET]->(svc)
		MERGE (attacker)-[:CLOUDFORMATION_UPDATESTACKSET]->(svc)
		MERGE (attacker)-[:`COGNITO-IDENTITY_SETIDENTITYPOOLROLES`]->(svc)
		MERGE (attacker)-[:ECS_CREATESERVICE]->(svc)
		MERGE (attacker)-[:ECS_STARTTASK]->(svc)
		MERGE (attacker)-[:ELASTICMAPREDUCE_RUNJOBFLOW]->(svc)
		MERGE (attacker)-[:`EMR-SERVERLESS_CREATEAPPLICATION`]->(svc)
		MERGE (attacker)-[:GAMELIFT_CREATEFLEET]->(svc)
		MERGE (attacker)-[:GLUE_CREATEDEVENDPOINT]->(svc)
		MERGE (attacker)-[:GLUE_UPDATEJOB]->(svc)
		MERGE (attacker)-[:GLUE_CREATESESSION]->(svc)
		MERGE (attacker)-[:IMAGEBUILDER_CREATEINFRASTRUCTURECONFIGURATION]->(svc)
		MERGE (attacker)-[:KINESISANALYTICS_CREATEAPPLICATION]->(svc)
		MERGE (attacker)-[:LAMBDA_UPDATEFUNCTIONCODE]->(svc)
		MERGE (attacker)-[:LAMBDA_ADDPERMISSION]->(svc)
		MERGE (attacker)-[:OMICS_CREATEWORKFLOW]->(svc)
		MERGE (attacker)-[:SCHEDULER_CREATESCHEDULE]->(svc)
		MERGE (attacker)-[:SSM_STARTAUTOMATIONEXECUTION]->(svc)
		MERGE (attacker)-[:STATES_CREATESTATEMACHINE]->(svc)
		MERGE (attacker)-[:STATES_UPDATESTATEMACHINE]->(svc)
	`, attackerARN, victimARN, roleARN, svcResourceARN)

	_, err = db.Query(ctx, seedCypher, nil)
	require.NoError(t, err, "seed graph")

	// Run the full enrichment pipeline.
	err = EnrichAWS(ctx, db)
	require.NoError(t, err, "EnrichAWS should succeed")

	// Count total CAN_PRIVESC edges originating from the attacker.
	result, err := db.Query(ctx,
		fmt.Sprintf(`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->() RETURN count(r) AS n`, attackerARN),
		nil)
	require.NoError(t, err)
	require.Len(t, result.Records, 1)

	n, _ := toInt64(result.Records[0]["n"])
	t.Logf("attacker CAN_PRIVESC edge count after EnrichAWS: %d", n)
	assert.GreaterOrEqual(t, int(n), 30,
		"attacker with all new-method permissions should have at least 30 CAN_PRIVESC edges")
}

// toInt64 coerces common numeric types returned by the Neo4j driver to int64.
func toInt64(v interface{}) (int64, bool) {
	switch x := v.(type) {
	case int64:
		return x, true
	case int:
		return int64(x), true
	case float64:
		return int64(x), true
	}
	return 0, false
}
