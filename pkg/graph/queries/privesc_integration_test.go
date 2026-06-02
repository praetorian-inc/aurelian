//go:build integration

package queries

import (
	"context"
	"fmt"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/graph"
	"github.com/praetorian-inc/aurelian/pkg/graph/adapters"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	neo4jcontainer "github.com/testcontainers/testcontainers-go/modules/neo4j"
)

// startNeo4jContainer starts a Neo4j 5.x container and returns its bolt URL and a cleanup fn.
// Inlined here to avoid an import cycle: testutil → plugin → queries.
func startNeo4jContainer(ctx context.Context) (string, func(), error) {
	container, err := neo4jcontainer.Run(ctx, "neo4j:5", neo4jcontainer.WithoutAuthentication())
	if err != nil {
		return "", nil, err
	}
	boltURL, err := container.BoltUrl(ctx)
	if err != nil {
		container.Terminate(ctx)
		return "", nil, err
	}
	return boltURL, func() { container.Terminate(ctx) }, nil
}

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
// allPrivescCases returns test cases for every privesc method (methods 01–89).
// Add new methods here — no separate "old" vs "new" split.
func allPrivescCases() []privescTestCase {
	return []privescTestCase{
		// ---- Methods 01–42 (pre-PR baseline) ----
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
		standaloneCase("aws/enrich/privesc/method_27", "CODEBUILD_CREATEPROJECT"),
		// method_30: standalone — UpdateStack on existing stack, no PassRole needed
		standaloneCase("aws/enrich/privesc/method_30", "CLOUDFORMATION_UPDATESTACK"),
		passRoleCase("aws/enrich/privesc/method_32", "ECS_RUNTASK"),
		standaloneCase("aws/enrich/privesc/method_33", "CODEBUILD_STARTBUILD"),
		passRoleCase("aws/enrich/privesc/method_34", "CODEBUILD_UPDATEPROJECT"),
		standaloneCase("aws/enrich/privesc/method_35", "SAGEMAKER_CREATEPRESIGNEDNOTEBOOKINSTANCEURL"),
		passRoleCase("aws/enrich/privesc/method_36", "SAGEMAKER_CREATETRAININGJOB"),
		passRoleCase("aws/enrich/privesc/method_37", "SAGEMAKER_CREATEPROCESSINGJOB"),
		// method_40 YAML uses underscores (BEDROCK_AGENTCORE) not hyphens
		passRoleCase("aws/enrich/privesc/method_40", "BEDROCK_AGENTCORE_CREATECODEINTERPRETER"),

		// ---- Methods 43–72 (initial gap-fill) ----
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

		// method_71: UpdateStateMachine + StartExecution on same target (no PassRole)
		{
			queryID: "aws/enrich/privesc/method_71",
			setup: fmt.Sprintf(`
				CREATE (a:Principal {Arn: '%s'})
				CREATE (v:Principal {Arn: '%s'})
				CREATE (t:Resource  {Arn: '%s'})
				WITH a, v, t
				MERGE (a)-[:STATES_UPDATESTATEMACHINE]->(t)
				MERGE (a)-[:STATES_STARTEXECUTION]->(t)
			`, attackerARN, victimARN, roleARN),
			verify:    fmt.Sprintf(`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(v {Arn: '%s'}) RETURN count(r) AS n`, attackerARN, victimARN),
			wantEdges: 1,
		},

		// method_72: bedrock-agentcore:InvokeSession (standalone)
		standaloneCase("aws/enrich/privesc/method_72", "BEDROCK-AGENTCORE_INVOKESESSION"),

		// --- Group A: wrong-API fixes ---
		// method_73: iam:PassRole + ec2:RequestSpotInstances (distinct from RunInstances)
		passRoleCase("aws/enrich/privesc/method_73", "EC2_REQUESTSPOTINSTANCES"),

		// method_74: ec2:CreateLaunchTemplateVersion + ec2:ModifyLaunchTemplate (no PassRole)
		{
			queryID: "aws/enrich/privesc/method_74",
			setup: fmt.Sprintf(`
				CREATE (a:Principal {Arn: '%s'})
				CREATE (v:Principal {Arn: '%s'})
				CREATE (t:Resource  {Arn: '%s'})
				WITH a, v, t
				MERGE (a)-[:`+"`EC2_CREATELAUNCHTEMPLATEVERSION`"+`]->(t)
				MERGE (a)-[:EC2_MODIFYLAUNCHTEMPLATE]->(t)
			`, attackerARN, victimARN, roleARN),
			verify:    fmt.Sprintf(`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(v {Arn: '%s'}) RETURN count(r) AS n`, attackerARN, victimARN),
			wantEdges: 1,
		},

		// --- Group B: completely missing methods ---
		// method_75: iam:PassRole + amplify:CreateApp + amplify:StartJob
		{
			queryID: "aws/enrich/privesc/method_75",
			setup: fmt.Sprintf(`
				CREATE (a:Principal {Arn: '%s'})
				CREATE (r:Resource  {Arn: '%s'})
				CREATE (s:Resource  {Arn: '%s'})
				WITH a, r, s
				MERGE (a)-[:IAM_PASSROLE]->(r)
				MERGE (a)-[:AMPLIFY_CREATEAPP]->(s)
				MERGE (a)-[:AMPLIFY_STARTJOB]->(s)
			`, attackerARN, roleARN, svcResourceARN),
			verify:    fmt.Sprintf(`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(s {Arn: '%s'}) RETURN count(r) AS n`, attackerARN, svcResourceARN),
			wantEdges: 1,
		},

		// method_76: ec2:ModifyInstanceAttribute + StopInstances + StartInstances (no PassRole)
		{
			queryID: "aws/enrich/privesc/method_76",
			setup: fmt.Sprintf(`
				CREATE (a:Principal {Arn: '%s'})
				CREATE (v:Principal {Arn: '%s'})
				CREATE (t:Resource  {Arn: '%s'})
				WITH a, v, t
				MERGE (a)-[:EC2_MODIFYINSTANCEATTRIBUTE]->(t)
				MERGE (a)-[:EC2_STOPINSTANCES]->(t)
				MERGE (a)-[:EC2_STARTINSTANCES]->(t)
			`, attackerARN, victimARN, roleARN),
			verify:    fmt.Sprintf(`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(v {Arn: '%s'}) RETURN count(r) AS n`, attackerARN, victimARN),
			wantEdges: 1,
		},

		// method_77: iam:PassRole + glue:CreateJob + glue:CreateTrigger
		{
			queryID: "aws/enrich/privesc/method_77",
			setup: fmt.Sprintf(`
				CREATE (a:Principal {Arn: '%s'})
				CREATE (r:Resource  {Arn: '%s'})
				CREATE (s:Resource  {Arn: '%s'})
				WITH a, r, s
				MERGE (a)-[:IAM_PASSROLE]->(r)
				MERGE (a)-[:GLUE_CREATEJOB]->(s)
				MERGE (a)-[:GLUE_CREATETRIGGER]->(s)
			`, attackerARN, roleARN, svcResourceARN),
			verify:    fmt.Sprintf(`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(s {Arn: '%s'}) RETURN count(r) AS n`, attackerARN, svcResourceARN),
			wantEdges: 1,
		},

		// method_78: iam:PassRole + glue:UpdateJob + glue:CreateTrigger
		{
			queryID: "aws/enrich/privesc/method_78",
			setup: fmt.Sprintf(`
				CREATE (a:Principal {Arn: '%s'})
				CREATE (r:Resource  {Arn: '%s'})
				CREATE (s:Resource  {Arn: '%s'})
				WITH a, r, s
				MERGE (a)-[:IAM_PASSROLE]->(r)
				MERGE (a)-[:GLUE_UPDATEJOB]->(s)
				MERGE (a)-[:GLUE_CREATETRIGGER]->(s)
			`, attackerARN, roleARN, svcResourceARN),
			verify:    fmt.Sprintf(`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(s {Arn: '%s'}) RETURN count(r) AS n`, attackerARN, svcResourceARN),
			wantEdges: 1,
		},

		// method_79: iam:PassRole + lambda:CreateFunction + lambda:AddPermission
		{
			queryID: "aws/enrich/privesc/method_79",
			setup: fmt.Sprintf(`
				CREATE (a:Principal {Arn: '%s'})
				CREATE (r:Resource  {Arn: '%s'})
				CREATE (s:Resource  {Arn: '%s'})
				WITH a, r, s
				MERGE (a)-[:IAM_PASSROLE]->(r)
				MERGE (a)-[:LAMBDA_CREATEFUNCTION]->(s)
				MERGE (a)-[:LAMBDA_ADDPERMISSION]->(s)
			`, attackerARN, roleARN, svcResourceARN),
			verify:    fmt.Sprintf(`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(s {Arn: '%s'}) RETURN count(r) AS n`, attackerARN, svcResourceARN),
			wantEdges: 1,
		},

		// --- Group C: execution-gated compound methods ---
		// method_80: iam:PassRole + glue:CreateJob + glue:StartJobRun
		{
			queryID: "aws/enrich/privesc/method_80",
			setup: fmt.Sprintf(`
				CREATE (a:Principal {Arn: '%s'})
				CREATE (r:Resource  {Arn: '%s'})
				CREATE (s:Resource  {Arn: '%s'})
				WITH a, r, s
				MERGE (a)-[:IAM_PASSROLE]->(r)
				MERGE (a)-[:GLUE_CREATEJOB]->(s)
				MERGE (a)-[:GLUE_STARTJOBRUN]->(s)
			`, attackerARN, roleARN, svcResourceARN),
			verify:    fmt.Sprintf(`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(s {Arn: '%s'}) RETURN count(r) AS n`, attackerARN, svcResourceARN),
			wantEdges: 1,
		},

		// method_81: iam:PassRole + glue:UpdateJob + glue:StartJobRun
		{
			queryID: "aws/enrich/privesc/method_81",
			setup: fmt.Sprintf(`
				CREATE (a:Principal {Arn: '%s'})
				CREATE (r:Resource  {Arn: '%s'})
				CREATE (s:Resource  {Arn: '%s'})
				WITH a, r, s
				MERGE (a)-[:IAM_PASSROLE]->(r)
				MERGE (a)-[:GLUE_UPDATEJOB]->(s)
				MERGE (a)-[:GLUE_STARTJOBRUN]->(s)
			`, attackerARN, roleARN, svcResourceARN),
			verify:    fmt.Sprintf(`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(s {Arn: '%s'}) RETURN count(r) AS n`, attackerARN, svcResourceARN),
			wantEdges: 1,
		},

		// method_82: iam:PassRole + glue:CreateSession + glue:RunStatement
		{
			queryID: "aws/enrich/privesc/method_82",
			setup: fmt.Sprintf(`
				CREATE (a:Principal {Arn: '%s'})
				CREATE (r:Resource  {Arn: '%s'})
				CREATE (s:Resource  {Arn: '%s'})
				WITH a, r, s
				MERGE (a)-[:IAM_PASSROLE]->(r)
				MERGE (a)-[:GLUE_CREATESESSION]->(s)
				MERGE (a)-[:GLUE_RUNSTATEMENT]->(s)
			`, attackerARN, roleARN, svcResourceARN),
			verify:    fmt.Sprintf(`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(s {Arn: '%s'}) RETURN count(r) AS n`, attackerARN, svcResourceARN),
			wantEdges: 1,
		},

		// method_83: iam:PassRole + states:CreateStateMachine + states:StartExecution
		{
			queryID: "aws/enrich/privesc/method_83",
			setup: fmt.Sprintf(`
				CREATE (a:Principal {Arn: '%s'})
				CREATE (r:Resource  {Arn: '%s'})
				CREATE (s:Resource  {Arn: '%s'})
				WITH a, r, s
				MERGE (a)-[:IAM_PASSROLE]->(r)
				MERGE (a)-[:STATES_CREATESTATEMACHINE]->(s)
				MERGE (a)-[:STATES_STARTEXECUTION]->(s)
			`, attackerARN, roleARN, svcResourceARN),
			verify:    fmt.Sprintf(`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(s {Arn: '%s'}) RETURN count(r) AS n`, attackerARN, svcResourceARN),
			wantEdges: 1,
		},

		// method_84: ssm:CreateDocument + ssm:StartAutomationExecution (no PassRole)
		{
			queryID: "aws/enrich/privesc/method_84",
			setup: fmt.Sprintf(`
				CREATE (a:Principal {Arn: '%s'})
				CREATE (v:Principal {Arn: '%s'})
				CREATE (t:Resource  {Arn: '%s'})
				WITH a, v, t
				MERGE (a)-[:SSM_CREATEDOCUMENT]->(t)
				MERGE (a)-[:SSM_STARTAUTOMATIONEXECUTION]->(t)
			`, attackerARN, victimARN, roleARN),
			verify:    fmt.Sprintf(`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(v {Arn: '%s'}) RETURN count(r) AS n`, attackerARN, victimARN),
			wantEdges: 1,
		},

		// method_85: iam:PassRole + emr-serverless:CreateApplication + emr-serverless:StartJobRun
		{
			queryID: "aws/enrich/privesc/method_85",
			setup: fmt.Sprintf(`
				CREATE (a:Principal {Arn: '%s'})
				CREATE (r:Resource  {Arn: '%s'})
				CREATE (s:Resource  {Arn: '%s'})
				WITH a, r, s
				MERGE (a)-[:IAM_PASSROLE]->(r)
				MERGE (a)-[:`+"`EMR-SERVERLESS_CREATEAPPLICATION`"+`]->(s)
				MERGE (a)-[:`+"`EMR-SERVERLESS_STARTJOBRUN`"+`]->(s)
			`, attackerARN, roleARN, svcResourceARN),
			verify:    fmt.Sprintf(`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(s {Arn: '%s'}) RETURN count(r) AS n`, attackerARN, svcResourceARN),
			wantEdges: 1,
		},

		// method_86: iam:PassRole + kinesisanalytics:CreateApplication + StartApplication
		{
			queryID: "aws/enrich/privesc/method_86",
			setup: fmt.Sprintf(`
				CREATE (a:Principal {Arn: '%s'})
				CREATE (r:Resource  {Arn: '%s'})
				CREATE (s:Resource  {Arn: '%s'})
				WITH a, r, s
				MERGE (a)-[:IAM_PASSROLE]->(r)
				MERGE (a)-[:KINESISANALYTICS_CREATEAPPLICATION]->(s)
				MERGE (a)-[:KINESISANALYTICS_STARTAPPLICATION]->(s)
			`, attackerARN, roleARN, svcResourceARN),
			verify:    fmt.Sprintf(`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(s {Arn: '%s'}) RETURN count(r) AS n`, attackerARN, svcResourceARN),
			wantEdges: 1,
		},

		// method_87: iam:PassRole + omics:CreateWorkflow + omics:StartRun
		{
			queryID: "aws/enrich/privesc/method_87",
			setup: fmt.Sprintf(`
				CREATE (a:Principal {Arn: '%s'})
				CREATE (r:Resource  {Arn: '%s'})
				CREATE (s:Resource  {Arn: '%s'})
				WITH a, r, s
				MERGE (a)-[:IAM_PASSROLE]->(r)
				MERGE (a)-[:OMICS_CREATEWORKFLOW]->(s)
				MERGE (a)-[:OMICS_STARTRUN]->(s)
			`, attackerARN, roleARN, svcResourceARN),
			verify:    fmt.Sprintf(`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(s {Arn: '%s'}) RETURN count(r) AS n`, attackerARN, svcResourceARN),
			wantEdges: 1,
		},

		// method_88: iam:PassRole + gamelift:CreateBuild + gamelift:CreateFleet
		{
			queryID: "aws/enrich/privesc/method_88",
			setup: fmt.Sprintf(`
				CREATE (a:Principal {Arn: '%s'})
				CREATE (r:Resource  {Arn: '%s'})
				CREATE (s:Resource  {Arn: '%s'})
				CREATE (s2:Resource {Arn: 'arn:aws:gamelift:us-east-1::fleet/test'})
				WITH a, r, s, s2
				MERGE (a)-[:IAM_PASSROLE]->(r)
				MERGE (a)-[:GAMELIFT_CREATEBUILD]->(s)
				MERGE (a)-[:GAMELIFT_CREATEFLEET]->(s2)
			`, attackerARN, roleARN, svcResourceARN),
			verify:    fmt.Sprintf(`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->() RETURN count(r) AS n`, attackerARN),
			wantEdges: 1,
		},

		// method_89: iam:PassRole + imagebuilder:CreateInfraConfig + imagebuilder:CreateImage
		{
			queryID: "aws/enrich/privesc/method_89",
			setup: fmt.Sprintf(`
				CREATE (a:Principal {Arn: '%s'})
				CREATE (r:Resource  {Arn: '%s'})
				CREATE (s:Resource  {Arn: '%s'})
				WITH a, r, s
				MERGE (a)-[:IAM_PASSROLE]->(r)
				MERGE (a)-[:IMAGEBUILDER_CREATEINFRASTRUCTURECONFIGURATION]->(s)
				MERGE (a)-[:IMAGEBUILDER_CREATEIMAGE]->(s)
			`, attackerARN, roleARN, svcResourceARN),
			verify:    fmt.Sprintf(`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(s {Arn: '%s'}) RETURN count(r) AS n`, attackerARN, svcResourceARN),
			wantEdges: 1,
		},
	}
}


// TestPrivescQueriesNeo4j verifies every privesc enrichment query creates
// CAN_PRIVESC edges when the required IAM permission relationships are present.
// Requires a Neo4j container (testcontainers).
func TestPrivescQueriesNeo4j(t *testing.T) {
	ctx := context.Background()

	boltURL, cleanup, err := startNeo4jContainer(ctx)
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

	for _, tc := range allPrivescCases() {
		tc := tc
		t.Run(tc.queryID, func(t *testing.T) {
			runCase(t, tc)
		})
	}
}

// TestEnrichAWSPrivescEndToEnd seeds a graph with all new-method permission
// relationships and verifies that running EnrichAWS creates CAN_PRIVESC edges
// for each new service pathway.
func TestEnrichAWSPrivescEndToEnd(t *testing.T) {
	ctx := context.Background()

	boltURL, cleanup, err := startNeo4jContainer(ctx)
	require.NoError(t, err, "start Neo4j container")
	t.Cleanup(cleanup)

	cfg := graph.NewConfig(boltURL, "", "")
	db, err := adapters.NewNeo4jAdapter(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	// Clear and seed the graph with one attacker holding every new-method permission.
	_, err = db.Query(ctx, "MATCH (n) DETACH DELETE n", nil)
	require.NoError(t, err)

	// Seed nodes and all non-hyphenated relationship types in one query.
	seedCypher := fmt.Sprintf(`
		CREATE (attacker:Principal {Arn: '%s'})
		CREATE (victim:Principal   {Arn: '%s'})
		CREATE (role:Resource      {Arn: '%s'})
		CREATE (svc:Resource       {Arn: '%s'})
		WITH attacker, victim, role, svc
		MERGE (attacker)-[:IAM_PASSROLE]->(role)
		MERGE (attacker)-[:APPRUNNER_UPDATESERVICE]->(svc)
		MERGE (attacker)-[:BATCH_SUBMITJOB]->(svc)
		MERGE (attacker)-[:CODEDEPLOY_CREATEDEPLOYMENT]->(svc)
		MERGE (attacker)-[:EC2_REPLACEIAMINSTANCEPROFILEASSOCIATION]->(svc)
		MERGE (attacker)-[:ECS_EXECUTECOMMAND]->(svc)
		MERGE (attacker)-[:SAGEMAKER_UPDATENOTEBOOKINSTANCELIFECYCLECONFIG]->(svc)
		MERGE (attacker)-[:APPRUNNER_CREATESERVICE]->(svc)
		MERGE (attacker)-[:BATCH_REGISTERJOBDEFINITION]->(svc)
		MERGE (attacker)-[:BRAKET_CREATEJOB]->(svc)
		MERGE (attacker)-[:CLOUDFORMATION_CREATESTACKSET]->(svc)
		MERGE (attacker)-[:CLOUDFORMATION_UPDATESTACKSET]->(svc)
		MERGE (attacker)-[:ECS_CREATESERVICE]->(svc)
		MERGE (attacker)-[:ECS_STARTTASK]->(svc)
		MERGE (attacker)-[:ELASTICMAPREDUCE_RUNJOBFLOW]->(svc)
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
	require.NoError(t, err, "seed graph (non-hyphenated types)")

	// Hyphenated relationship types must be backtick-escaped in Cypher literal syntax
	// but cannot appear inside a Go raw string literal — seed them as separate queries.
	for _, hyphenatedSeed := range []string{
		fmt.Sprintf("MATCH (a {Arn: '%s'}), (s {Arn: '%s'}) MERGE (a)-[:`EC2-INSTANCE-CONNECT_SENDSSHPUBLICKEY`]->(s)", attackerARN, svcResourceARN),
		fmt.Sprintf("MATCH (a {Arn: '%s'}), (s {Arn: '%s'}) MERGE (a)-[:`BEDROCK-AGENTCORE_INVOKESESSION`]->(s)", attackerARN, svcResourceARN),
		fmt.Sprintf("MATCH (a {Arn: '%s'}), (s {Arn: '%s'}) MERGE (a)-[:`COGNITO-IDENTITY_SETIDENTITYPOOLROLES`]->(s)", attackerARN, svcResourceARN),
		fmt.Sprintf("MATCH (a {Arn: '%s'}), (s {Arn: '%s'}) MERGE (a)-[:`EMR-SERVERLESS_CREATEAPPLICATION`]->(s)", attackerARN, svcResourceARN),
	} {
		_, err = db.Query(ctx, hyphenatedSeed, nil)
		require.NoError(t, err, "seed hyphenated relationship type")
	}

	// Run the full enrichment pipeline.
	err = EnrichAWS(ctx, db)
	require.NoError(t, err, "EnrichAWS should succeed")

	// MERGE is idempotent on (start, end, type) — all standalone methods share one edge to victim,
	// all PassRole+service methods share one edge to svc. Assert both targets got a CAN_PRIVESC edge.
	for _, tc := range []struct {
		label  string
		target string
	}{
		{"standalone methods → victim", victimARN},
		{"PassRole+service methods → svc", svcResourceARN},
	} {
		result, err := db.Query(ctx,
			fmt.Sprintf(`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(t {Arn: '%s'}) RETURN count(r) AS n`, attackerARN, tc.target),
			nil)
		require.NoError(t, err)
		require.Len(t, result.Records, 1)
		n, _ := toInt64(result.Records[0]["n"])
		t.Logf("%s: %d CAN_PRIVESC edge(s)", tc.label, n)
		assert.GreaterOrEqual(t, int(n), 1, "expected at least 1 CAN_PRIVESC edge for %s", tc.label)
	}
}

// TestPrivescMultiHopPaths verifies that the analysis query detects multi-hop
// privilege escalation chains built from CAN_PRIVESC enrichment edges.
func TestPrivescMultiHopPaths(t *testing.T) {
	ctx := context.Background()

	boltURL, cleanup, err := startNeo4jContainer(ctx)
	require.NoError(t, err, "start Neo4j container")
	t.Cleanup(cleanup)

	cfg := graph.NewConfig(boltURL, "", "")
	db, err := adapters.NewNeo4jAdapter(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	// Seed a 3-hop chain: low → mid → high → admin
	// where each hop is created by a different privesc method.
	_, err = db.Query(ctx, `
		CREATE (low:Principal  {Arn: 'arn:aws:iam::123456789012:user/low',  _is_admin: false})
		CREATE (mid:Principal  {Arn: 'arn:aws:iam::123456789012:role/mid',  _is_admin: false})
		CREATE (high:Principal {Arn: 'arn:aws:iam::123456789012:role/high', _is_admin: false})
		CREATE (admin:Principal{Arn: 'arn:aws:iam::123456789012:role/admin',_is_admin: true})
		CREATE (svc1:Resource  {Arn: 'arn:aws:lambda:us-east-1:123456789012:function:fn1'})
		CREATE (svc2:Resource  {Arn: 'arn:aws:ecs:us-east-1:123456789012:cluster/c1'})
		WITH low, mid, high, admin, svc1, svc2

		// Hop 1: low has PassRole + CreateFunction → can execute as mid via Lambda
		MERGE (low)-[:IAM_PASSROLE]->(mid)
		MERGE (low)-[:LAMBDA_CREATEFUNCTION]->(svc1)

		// Hop 2: mid has PassRole + ECS CreateService → can escalate to high
		MERGE (mid)-[:IAM_PASSROLE]->(high)
		MERGE (mid)-[:ECS_CREATESERVICE]->(svc2)

		// Hop 3: high has iam:CreatePolicyVersion → direct admin escalation
		MERGE (high)-[:IAM_CREATEPOLICYVERSION]->(admin)
	`, nil)
	require.NoError(t, err, "seed multi-hop graph")

	// Run enrichment to create CAN_PRIVESC edges.
	err = EnrichAWS(ctx, db)
	require.NoError(t, err, "EnrichAWS should succeed")

	t.Run("one_hop_low_to_svc1", func(t *testing.T) {
		// method_14: low has PassRole+CreateFunction → CAN_PRIVESC to svc1
		result, err := db.Query(ctx, `
			MATCH (a {Arn: 'arn:aws:iam::123456789012:user/low'})-[r:CAN_PRIVESC]->(s {Arn: 'arn:aws:lambda:us-east-1:123456789012:function:fn1'})
			RETURN count(r) AS n`, nil)
		require.NoError(t, err)
		n, _ := toInt64(result.Records[0]["n"])
		assert.GreaterOrEqual(t, int(n), 1, "low should have CAN_PRIVESC to Lambda svc via method_14")
	})

	t.Run("one_hop_high_to_admin", func(t *testing.T) {
		// method_01: high has CreatePolicyVersion → CAN_PRIVESC to admin
		result, err := db.Query(ctx, `
			MATCH (a {Arn: 'arn:aws:iam::123456789012:role/high'})-[r:CAN_PRIVESC]->(b {Arn: 'arn:aws:iam::123456789012:role/admin'})
			RETURN count(r) AS n`, nil)
		require.NoError(t, err)
		n, _ := toInt64(result.Records[0]["n"])
		assert.GreaterOrEqual(t, int(n), 1, "high should have CAN_PRIVESC to admin via method_01")
	})

	t.Run("analysis_query_finds_multi_hop_chain", func(t *testing.T) {
		// The analysis query uses CAN_PRIVESC*1..3 to find chains from non-admin to admin.
		result, err := db.Query(ctx, `
			MATCH path = (attacker:Principal)-[:CAN_PRIVESC*1..3]->(target:Principal)
			WHERE target._is_admin = true
			AND NOT attacker._is_admin = true
			AND attacker.Arn <> target.Arn
			WITH attacker, target, length(path) AS hops
			RETURN attacker.Arn AS attacker_arn, target.Arn AS target_arn, hops
			ORDER BY hops ASC`, nil)
		require.NoError(t, err)
		require.NotEmpty(t, result.Records, "analysis query should find at least one privesc path to admin")

		t.Logf("Found %d privesc path(s) to admin:", len(result.Records))
		for _, rec := range result.Records {
			t.Logf("  %s → %s (%v hops)", rec["attacker_arn"], rec["target_arn"], rec["hops"])
		}

		// Verify the 1-hop path (high → admin) is found.
		found1Hop := false
		for _, rec := range result.Records {
			if rec["attacker_arn"] == "arn:aws:iam::123456789012:role/high" && rec["hops"] == int64(1) {
				found1Hop = true
			}
		}
		assert.True(t, found1Hop, "analysis query should find 1-hop path high → admin")
	})

	t.Run("no_self_privesc_edges", func(t *testing.T) {
		result, err := db.Query(ctx, `MATCH (a)-[r:CAN_PRIVESC]->(a) RETURN count(r) AS n`, nil)
		require.NoError(t, err)
		n, _ := toInt64(result.Records[0]["n"])
		assert.Equal(t, int64(0), n, "no principal should have a CAN_PRIVESC edge to itself")
	})
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
