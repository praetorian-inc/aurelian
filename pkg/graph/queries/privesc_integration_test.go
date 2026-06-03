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
	attackerARN    = "arn:aws:iam::123456789012:user/attacker"
	victimARN      = "arn:aws:iam::123456789012:user/victim"
	roleARN        = "arn:aws:iam::123456789012:role/target-role"
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

// passRoleCase builds a test case for pre-existing PassRole+service methods (14–42).
// These methods still create CAN_PRIVESC to the service resource node (pre-existing
// Concern B design — tracked in Linear for a follow-up fix).
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

// passRoleCaseFanOut builds a test case for new PassRole+service methods (43–89).
// After the CodeRabbit-validated fix, these methods create CAN_PRIVESC to the
// specific passed IAM role (victim = passed role) rather than all Principals.
// The passed role is created as :Principal (matching real IAM role node labeling).
func passRoleCaseFanOut(queryID, svcPermType string) privescTestCase {
	return privescTestCase{
		queryID: queryID,
		setup: fmt.Sprintf(`
			CREATE (a:Principal {Arn: '%s'})
			CREATE (r:Principal {Arn: '%s'})
			CREATE (s:Resource  {Arn: '%s'})
			WITH a, r, s
			MERGE (a)-[:IAM_PASSROLE]->(r)
			MERGE (a)-[:`+"`%s`"+`]->(s)
		`, attackerARN, roleARN, svcResourceARN, svcPermType),
		verify:    fmt.Sprintf(`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(v {Arn: '%s'}) RETURN count(r) AS n`, attackerARN, roleARN),
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
		standaloneCase("aws/enrich/privesc/method_26", "CODESTAR_CREATEPROJECT"),
		standaloneCase("aws/enrich/privesc/method_27", "CODEBUILD_CREATEPROJECT"),
		standaloneCase("aws/enrich/privesc/method_28", "IAM_CREATESERVICELINKEDROLE"),
		// method_29: standalone — UpdateDevEndpoint on existing Glue endpoint (no PassRole)
		standaloneCase("aws/enrich/privesc/method_29", "GLUE_UPDATEDEVENDPOINT"),
		// method_30: standalone — UpdateStack on existing stack, no PassRole needed
		standaloneCase("aws/enrich/privesc/method_30", "CLOUDFORMATION_UPDATESTACK"),
		// method_31: CreateChangeSet + ExecuteChangeSet on the SAME stack (no PassRole)
		{
			queryID: "aws/enrich/privesc/method_31",
			setup: fmt.Sprintf(`
				CREATE (a:Principal {Arn: '%s'})
				CREATE (v:Principal {Arn: '%s'})
				CREATE (t:Resource  {Arn: '%s'})
				WITH a, v, t
				MERGE (a)-[:CLOUDFORMATION_CREATECHANGESET]->(t)
				MERGE (a)-[:CLOUDFORMATION_EXECUTECHANGESET]->(t)
			`, attackerARN, victimARN, roleARN),
			verify:    fmt.Sprintf(`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(v {Arn: '%s'}) RETURN count(r) AS n`, attackerARN, victimARN),
			wantEdges: 1,
		},
		passRoleCase("aws/enrich/privesc/method_32", "ECS_RUNTASK"),
		standaloneCase("aws/enrich/privesc/method_33", "CODEBUILD_STARTBUILD"),
		passRoleCase("aws/enrich/privesc/method_34", "CODEBUILD_UPDATEPROJECT"),
		standaloneCase("aws/enrich/privesc/method_35", "SAGEMAKER_CREATEPRESIGNEDNOTEBOOKINSTANCEURL"),
		passRoleCase("aws/enrich/privesc/method_36", "SAGEMAKER_CREATETRAININGJOB"),
		passRoleCase("aws/enrich/privesc/method_37", "SAGEMAKER_CREATEPROCESSINGJOB"),
		// method_39: lambda:UpdateFunctionCode + lambda:InvokeFunction (no PassRole — escalates via Lambda execution role)
		{
			queryID: "aws/enrich/privesc/method_39",
			setup: fmt.Sprintf(`
					CREATE (a:Principal {Arn: '%s'})
					CREATE (r:Principal {Arn: '%s'})
					CREATE (f:Resource  {Arn: '%s'})
					WITH a, r, f
					MERGE (a)-[:LAMBDA_UPDATEFUNCTIONCODE]->(f)
					MERGE (a)-[:LAMBDA_INVOKEFUNCTION]->(f)
					MERGE (f)-[:HAS_ROLE]->(r)
				`, attackerARN, roleARN, svcResourceARN),
			verify:    fmt.Sprintf(`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(v {Arn: '%s'}) RETURN count(r) AS n`, attackerARN, roleARN),
			wantEdges: 1,
		},
		// method_38: iam:PassRole + ec2:CreateLaunchTemplate + autoscaling:CreateAutoScalingGroup
		{
			queryID: "aws/enrich/privesc/method_38",
			setup: fmt.Sprintf(`
				CREATE (a:Principal {Arn: '%s'})
				CREATE (r:Principal {Arn: '%s'})
				CREATE (s:Resource  {Arn: '%s'})
				WITH a, r, s
				MERGE (a)-[:IAM_PASSROLE]->(r)
				MERGE (a)-[:EC2_CREATELAUNCHTEMPLATE]->(s)
				MERGE (a)-[:AUTOSCALING_CREATEAUTOSCALINGGROUP]->(s)
			`, attackerARN, roleARN, svcResourceARN),
			verify:    fmt.Sprintf(`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(v {Arn: '%s'}) RETURN count(r) AS n`, attackerARN, roleARN),
			wantEdges: 1,
		},
		// method_40: hyphens preserved by normalizer → BEDROCK-AGENTCORE_CREATECODEINTERPRETER (fan-out fixed)
		passRoleCaseFanOut("aws/enrich/privesc/method_40", "BEDROCK-AGENTCORE_CREATECODEINTERPRETER"),
		// method_41: iam:PassRole + (iam:PutRolePolicy or iam:AttachRolePolicy) on same role
		{
			queryID: "aws/enrich/privesc/method_41",
			setup: fmt.Sprintf(`
				CREATE (a:Principal {Arn: '%s'})
				CREATE (r:Role      {Arn: '%s'})
				WITH a, r
				MERGE (a)-[:IAM_PUTROLEPOLICY]->(r)
				MERGE (a)-[:IAM_PASSROLE]->(r)
			`, attackerARN, roleARN),
			verify:    fmt.Sprintf(`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(t {Arn: '%s'}) RETURN count(r) AS n`, attackerARN, roleARN),
			wantEdges: 1,
		},
		// method_42: iam:UpdateAssumeRolePolicy + iam:PassRole on same role
		{
			queryID: "aws/enrich/privesc/method_42",
			setup: fmt.Sprintf(`
				CREATE (a:Principal {Arn: '%s'})
				CREATE (r:Role      {Arn: '%s'})
				WITH a, r
				MERGE (a)-[:IAM_UPDATEASSUMEROLEPOLICY]->(r)
				MERGE (a)-[:IAM_PASSROLE]->(r)
			`, attackerARN, roleARN),
			verify:    fmt.Sprintf(`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(t {Arn: '%s'}) RETURN count(r) AS n`, attackerARN, roleARN),
			wantEdges: 1,
		},

		// ---- Methods 43–72 (initial gap-fill) ----
		// method_43: iam:PassRole + apprunner:CreateService
		passRoleCaseFanOut("aws/enrich/privesc/method_43", "APPRUNNER_CREATESERVICE"),

		// method_44: apprunner:UpdateService (standalone — no PassRole required)
		standaloneCase("aws/enrich/privesc/method_44", "APPRUNNER_UPDATESERVICE"),

		// method_45: iam:PassRole + batch:RegisterJobDefinition
		passRoleCaseFanOut("aws/enrich/privesc/method_45", "BATCH_REGISTERJOBDEFINITION"),

		// method_46: batch:SubmitJob (standalone)
		standaloneCase("aws/enrich/privesc/method_46", "BATCH_SUBMITJOB"),

		// method_47: iam:PassRole + braket:CreateJob
		passRoleCaseFanOut("aws/enrich/privesc/method_47", "BRAKET_CREATEJOB"),

		// method_48: iam:PassRole + cloudformation:CreateStackSet
		passRoleCaseFanOut("aws/enrich/privesc/method_48", "CLOUDFORMATION_CREATESTACKSET"),

		// method_49: iam:PassRole + cloudformation:UpdateStackSet
		passRoleCaseFanOut("aws/enrich/privesc/method_49", "CLOUDFORMATION_UPDATESTACKSET"),

		// method_50: codedeploy:CreateDeployment (standalone)
		standaloneCase("aws/enrich/privesc/method_50", "CODEDEPLOY_CREATEDEPLOYMENT"),

		// method_51: iam:PassRole + cognito-identity:SetIdentityPoolRoles
		passRoleCaseFanOut("aws/enrich/privesc/method_51", "COGNITO-IDENTITY_SETIDENTITYPOOLROLES"),

		// method_52: ec2-instance-connect:SendSSHPublicKey (standalone)
		standaloneCase("aws/enrich/privesc/method_52", "EC2-INSTANCE-CONNECT_SENDSSHPUBLICKEY"),

		// method_53: ec2:ReplaceIamInstanceProfileAssociation (standalone)
		standaloneCase("aws/enrich/privesc/method_53", "EC2_REPLACEIAMINSTANCEPROFILEASSOCIATION"),

		// method_54: iam:PassRole + ecs:CreateService
		passRoleCaseFanOut("aws/enrich/privesc/method_54", "ECS_CREATESERVICE"),

		// method_55: iam:PassRole + ecs:StartTask
		passRoleCaseFanOut("aws/enrich/privesc/method_55", "ECS_STARTTASK"),

		// method_56: ecs:ExecuteCommand (standalone)
		standaloneCase("aws/enrich/privesc/method_56", "ECS_EXECUTECOMMAND"),

		// method_57: iam:PassRole + elasticmapreduce:RunJobFlow
		passRoleCaseFanOut("aws/enrich/privesc/method_57", "ELASTICMAPREDUCE_RUNJOBFLOW"),

		// method_58: iam:PassRole + emr-serverless:CreateApplication
		passRoleCaseFanOut("aws/enrich/privesc/method_58", "EMR-SERVERLESS_CREATEAPPLICATION"),

		// method_59: iam:PassRole + gamelift:CreateFleet
		passRoleCaseFanOut("aws/enrich/privesc/method_59", "GAMELIFT_CREATEFLEET"),

		// method_60: iam:PassRole + glue:CreateDevEndpoint
		passRoleCaseFanOut("aws/enrich/privesc/method_60", "GLUE_CREATEDEVENDPOINT"),

		// method_61: iam:PassRole + glue:UpdateJob
		passRoleCaseFanOut("aws/enrich/privesc/method_61", "GLUE_UPDATEJOB"),

		// method_62: iam:PassRole + glue:CreateSession
		passRoleCaseFanOut("aws/enrich/privesc/method_62", "GLUE_CREATESESSION"),

		// method_63: iam:PassRole + imagebuilder:CreateInfrastructureConfiguration
		passRoleCaseFanOut("aws/enrich/privesc/method_63", "IMAGEBUILDER_CREATEINFRASTRUCTURECONFIGURATION"),

		// method_64: iam:PassRole + kinesisanalytics:CreateApplication
		passRoleCaseFanOut("aws/enrich/privesc/method_64", "KINESISANALYTICS_CREATEAPPLICATION"),

		// method_65: lambda:UpdateFunctionCode + lambda:AddPermission (no PassRole — escalates via Lambda execution role)
		{
			queryID: "aws/enrich/privesc/method_65",
			setup: fmt.Sprintf(`
				CREATE (a:Principal {Arn: '%s'})
				CREATE (r:Principal {Arn: '%s'})
				CREATE (f:Resource  {Arn: '%s'})
				WITH a, r, f
				MERGE (a)-[:LAMBDA_UPDATEFUNCTIONCODE]->(f)
				MERGE (a)-[:LAMBDA_ADDPERMISSION]->(f)
				MERGE (f)-[:HAS_ROLE]->(r)
			`, attackerARN, roleARN, svcResourceARN),
			verify:    fmt.Sprintf(`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(v {Arn: '%s'}) RETURN count(r) AS n`, attackerARN, roleARN),
			wantEdges: 1,
		},

		// method_66: iam:PassRole + omics:CreateWorkflow
		passRoleCaseFanOut("aws/enrich/privesc/method_66", "OMICS_CREATEWORKFLOW"),

		// method_67: sagemaker:UpdateNotebookInstanceLifecycleConfig (standalone)
		standaloneCase("aws/enrich/privesc/method_67", "SAGEMAKER_UPDATENOTEBOOKINSTANCELIFECYCLECONFIG"),

		// method_68: iam:PassRole + scheduler:CreateSchedule
		passRoleCaseFanOut("aws/enrich/privesc/method_68", "SCHEDULER_CREATESCHEDULE"),

		// method_69: iam:PassRole + ssm:StartAutomationExecution
		passRoleCaseFanOut("aws/enrich/privesc/method_69", "SSM_STARTAUTOMATIONEXECUTION"),

		// method_70: iam:PassRole + states:CreateStateMachine
		passRoleCaseFanOut("aws/enrich/privesc/method_70", "STATES_CREATESTATEMACHINE"),

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
		passRoleCaseFanOut("aws/enrich/privesc/method_73", "EC2_REQUESTSPOTINSTANCES"),

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
		// method_75: iam:PassRole + amplify:CreateApp + amplify:CreateBranch + amplify:StartJob (all same target)
		{
			queryID: "aws/enrich/privesc/method_75",
			setup: fmt.Sprintf(`
				CREATE (a:Principal {Arn: '%s'})
				CREATE (r:Principal {Arn: '%s'})
				CREATE (s:Resource  {Arn: '%s'})
				WITH a, r, s
				MERGE (a)-[:IAM_PASSROLE]->(r)
				MERGE (a)-[:AMPLIFY_CREATEAPP]->(s)
				MERGE (a)-[:AMPLIFY_CREATEBRANCH]->(s)
				MERGE (a)-[:AMPLIFY_STARTJOB]->(s)
			`, attackerARN, roleARN, svcResourceARN),
			verify:    fmt.Sprintf(`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(v {Arn: '%s'}) RETURN count(r) AS n`, attackerARN, roleARN),
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
				CREATE (r:Principal {Arn: '%s'})
				CREATE (s:Resource  {Arn: '%s'})
				WITH a, r, s
				MERGE (a)-[:IAM_PASSROLE]->(r)
				MERGE (a)-[:GLUE_CREATEJOB]->(s)
				MERGE (a)-[:GLUE_CREATETRIGGER]->(s)
			`, attackerARN, roleARN, svcResourceARN),
			verify:    fmt.Sprintf(`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(v {Arn: '%s'}) RETURN count(r) AS n`, attackerARN, roleARN),
			wantEdges: 1,
		},

		// method_78: iam:PassRole + glue:UpdateJob + glue:CreateTrigger
		{
			queryID: "aws/enrich/privesc/method_78",
			setup: fmt.Sprintf(`
				CREATE (a:Principal {Arn: '%s'})
				CREATE (r:Principal {Arn: '%s'})
				CREATE (s:Resource  {Arn: '%s'})
				WITH a, r, s
				MERGE (a)-[:IAM_PASSROLE]->(r)
				MERGE (a)-[:GLUE_UPDATEJOB]->(s)
				MERGE (a)-[:GLUE_CREATETRIGGER]->(s)
			`, attackerARN, roleARN, svcResourceARN),
			verify:    fmt.Sprintf(`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(v {Arn: '%s'}) RETURN count(r) AS n`, attackerARN, roleARN),
			wantEdges: 1,
		},

		// method_79: iam:PassRole + lambda:CreateFunction + lambda:AddPermission
		{
			queryID: "aws/enrich/privesc/method_79",
			setup: fmt.Sprintf(`
				CREATE (a:Principal {Arn: '%s'})
				CREATE (r:Principal {Arn: '%s'})
				CREATE (s:Resource  {Arn: '%s'})
				WITH a, r, s
				MERGE (a)-[:IAM_PASSROLE]->(r)
				MERGE (a)-[:LAMBDA_CREATEFUNCTION]->(s)
				MERGE (a)-[:LAMBDA_ADDPERMISSION]->(s)
			`, attackerARN, roleARN, svcResourceARN),
			verify:    fmt.Sprintf(`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(v {Arn: '%s'}) RETURN count(r) AS n`, attackerARN, roleARN),
			wantEdges: 1,
		},

		// --- Group C: execution-gated compound methods ---
		// method_80: iam:PassRole + glue:CreateJob + glue:StartJobRun
		{
			queryID: "aws/enrich/privesc/method_80",
			setup: fmt.Sprintf(`
				CREATE (a:Principal {Arn: '%s'})
				CREATE (r:Principal {Arn: '%s'})
				CREATE (s:Resource  {Arn: '%s'})
				WITH a, r, s
				MERGE (a)-[:IAM_PASSROLE]->(r)
				MERGE (a)-[:GLUE_CREATEJOB]->(s)
				MERGE (a)-[:GLUE_STARTJOBRUN]->(s)
			`, attackerARN, roleARN, svcResourceARN),
			verify:    fmt.Sprintf(`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(v {Arn: '%s'}) RETURN count(r) AS n`, attackerARN, roleARN),
			wantEdges: 1,
		},

		// method_81: iam:PassRole + glue:UpdateJob + glue:StartJobRun
		{
			queryID: "aws/enrich/privesc/method_81",
			setup: fmt.Sprintf(`
				CREATE (a:Principal {Arn: '%s'})
				CREATE (r:Principal {Arn: '%s'})
				CREATE (s:Resource  {Arn: '%s'})
				WITH a, r, s
				MERGE (a)-[:IAM_PASSROLE]->(r)
				MERGE (a)-[:GLUE_UPDATEJOB]->(s)
				MERGE (a)-[:GLUE_STARTJOBRUN]->(s)
			`, attackerARN, roleARN, svcResourceARN),
			verify:    fmt.Sprintf(`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(v {Arn: '%s'}) RETURN count(r) AS n`, attackerARN, roleARN),
			wantEdges: 1,
		},

		// method_82: iam:PassRole + glue:CreateSession + glue:RunStatement
		{
			queryID: "aws/enrich/privesc/method_82",
			setup: fmt.Sprintf(`
				CREATE (a:Principal {Arn: '%s'})
				CREATE (r:Principal {Arn: '%s'})
				CREATE (s:Resource  {Arn: '%s'})
				WITH a, r, s
				MERGE (a)-[:IAM_PASSROLE]->(r)
				MERGE (a)-[:GLUE_CREATESESSION]->(s)
				MERGE (a)-[:GLUE_RUNSTATEMENT]->(s)
			`, attackerARN, roleARN, svcResourceARN),
			verify:    fmt.Sprintf(`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(v {Arn: '%s'}) RETURN count(r) AS n`, attackerARN, roleARN),
			wantEdges: 1,
		},

		// method_83: iam:PassRole + states:CreateStateMachine + states:StartExecution
		{
			queryID: "aws/enrich/privesc/method_83",
			setup: fmt.Sprintf(`
				CREATE (a:Principal {Arn: '%s'})
				CREATE (r:Principal {Arn: '%s'})
				CREATE (s:Resource  {Arn: '%s'})
				WITH a, r, s
				MERGE (a)-[:IAM_PASSROLE]->(r)
				MERGE (a)-[:STATES_CREATESTATEMACHINE]->(s)
				MERGE (a)-[:STATES_STARTEXECUTION]->(s)
			`, attackerARN, roleARN, svcResourceARN),
			verify:    fmt.Sprintf(`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(v {Arn: '%s'}) RETURN count(r) AS n`, attackerARN, roleARN),
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
				CREATE (r:Principal {Arn: '%s'})
				CREATE (s:Resource  {Arn: '%s'})
				WITH a, r, s
				MERGE (a)-[:IAM_PASSROLE]->(r)
				MERGE (a)-[:`+"`EMR-SERVERLESS_CREATEAPPLICATION`"+`]->(s)
				MERGE (a)-[:`+"`EMR-SERVERLESS_STARTJOBRUN`"+`]->(s)
			`, attackerARN, roleARN, svcResourceARN),
			verify:    fmt.Sprintf(`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(v {Arn: '%s'}) RETURN count(r) AS n`, attackerARN, roleARN),
			wantEdges: 1,
		},

		// method_86: iam:PassRole + kinesisanalytics:CreateApplication + StartApplication
		{
			queryID: "aws/enrich/privesc/method_86",
			setup: fmt.Sprintf(`
				CREATE (a:Principal {Arn: '%s'})
				CREATE (r:Principal {Arn: '%s'})
				CREATE (s:Resource  {Arn: '%s'})
				WITH a, r, s
				MERGE (a)-[:IAM_PASSROLE]->(r)
				MERGE (a)-[:KINESISANALYTICS_CREATEAPPLICATION]->(s)
				MERGE (a)-[:KINESISANALYTICS_STARTAPPLICATION]->(s)
			`, attackerARN, roleARN, svcResourceARN),
			verify:    fmt.Sprintf(`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(v {Arn: '%s'}) RETURN count(r) AS n`, attackerARN, roleARN),
			wantEdges: 1,
		},

		// method_87: iam:PassRole + omics:CreateWorkflow + omics:StartRun
		{
			queryID: "aws/enrich/privesc/method_87",
			setup: fmt.Sprintf(`
				CREATE (a:Principal {Arn: '%s'})
				CREATE (r:Principal {Arn: '%s'})
				CREATE (s:Resource  {Arn: '%s'})
				WITH a, r, s
				MERGE (a)-[:IAM_PASSROLE]->(r)
				MERGE (a)-[:OMICS_CREATEWORKFLOW]->(s)
				MERGE (a)-[:OMICS_STARTRUN]->(s)
			`, attackerARN, roleARN, svcResourceARN),
			verify:    fmt.Sprintf(`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(v {Arn: '%s'}) RETURN count(r) AS n`, attackerARN, roleARN),
			wantEdges: 1,
		},

		// method_88: iam:PassRole + gamelift:CreateBuild + gamelift:CreateFleet
		// CreateBuild and CreateFleet target different resource types — both check same passed role.
		{
			queryID: "aws/enrich/privesc/method_88",
			setup: fmt.Sprintf(`
				CREATE (a:Principal {Arn: '%s'})
				CREATE (r:Principal {Arn: '%s'})
				CREATE (s:Resource  {Arn: '%s'})
				CREATE (s2:Resource {Arn: 'arn:aws:gamelift:us-east-1::fleet/test'})
				WITH a, r, s, s2
				MERGE (a)-[:IAM_PASSROLE]->(r)
				MERGE (a)-[:GAMELIFT_CREATEBUILD]->(s)
				MERGE (a)-[:GAMELIFT_CREATEFLEET]->(s2)
			`, attackerARN, roleARN, svcResourceARN),
			verify:    fmt.Sprintf(`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(v {Arn: '%s'}) RETURN count(r) AS n`, attackerARN, roleARN),
			wantEdges: 1,
		},

		// method_89: iam:PassRole + imagebuilder:CreateInfraConfig + imagebuilder:CreateImage
		{
			queryID: "aws/enrich/privesc/method_89",
			setup: fmt.Sprintf(`
				CREATE (a:Principal {Arn: '%s'})
				CREATE (r:Principal {Arn: '%s'})
				CREATE (s:Resource  {Arn: '%s'})
				WITH a, r, s
				MERGE (a)-[:IAM_PASSROLE]->(r)
				MERGE (a)-[:IMAGEBUILDER_CREATEINFRASTRUCTURECONFIGURATION]->(s)
				MERGE (a)-[:IMAGEBUILDER_CREATEIMAGE]->(s)
			`, attackerARN, roleARN, svcResourceARN),
			verify:    fmt.Sprintf(`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(v {Arn: '%s'}) RETURN count(r) AS n`, attackerARN, roleARN),
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
	// role must be :Principal so the scoped PassRole queries can find it as victim.
	seedCypher := fmt.Sprintf(`
		CREATE (attacker:Principal {Arn: '%s'})
		CREATE (role:Principal     {Arn: '%s'})
		CREATE (svc:Resource       {Arn: '%s'})
		WITH attacker, role, svc
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
	`, attackerARN, roleARN, svcResourceARN)

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

	// After the scoped fix, PassRole methods create CAN_PRIVESC to the passed role (roleARN).
	// MERGE deduplicates edges per (attacker, role) — all PassRole methods share this 1 edge.
	result, err := db.Query(ctx,
		fmt.Sprintf(`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(v {Arn: '%s'}) RETURN count(r) AS n`, attackerARN, roleARN),
		nil)
	require.NoError(t, err)
	require.Len(t, result.Records, 1)
	n, _ := toInt64(result.Records[0]["n"])
	t.Logf("CAN_PRIVESC edges attacker→role: %d", n)
	assert.GreaterOrEqual(t, int(n), 1, "enrichment should produce at least 1 CAN_PRIVESC edge to the passed role")
}

// TestPrivescMultiHopPaths verifies that EnrichAWS produces CAN_PRIVESC edges
// that form real principal-to-principal chains detectable by the analysis query.
// Uses standalone IAM methods (which fire to ALL other principals) to build chains.
func TestPrivescMultiHopPaths(t *testing.T) {
	ctx := context.Background()

	boltURL, cleanup, err := startNeo4jContainer(ctx)
	require.NoError(t, err, "start Neo4j container")
	t.Cleanup(cleanup)

	cfg := graph.NewConfig(boltURL, "", "")
	db, err := adapters.NewNeo4jAdapter(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	// Seed four Principal nodes with IAM permission edges so EnrichAWS creates
	// CAN_PRIVESC edges between them via standalone methods (methods 01–13 fire
	// for ALL other principals, building a fully-connected escalation graph).
	_, err = db.Query(ctx, `
		CREATE (low:Principal  {Arn: 'arn:aws:iam::123456789012:user/low',  _is_admin: false})
		CREATE (mid:Principal  {Arn: 'arn:aws:iam::123456789012:role/mid',  _is_admin: false})
		CREATE (high:Principal {Arn: 'arn:aws:iam::123456789012:role/high', _is_admin: false})
		CREATE (admin:Principal{Arn: 'arn:aws:iam::123456789012:role/admin',_is_admin: true})
		CREATE (policy:Resource{Arn: 'arn:aws:iam::123456789012:policy/p'})
		WITH low, mid, high, admin, policy

		// low: CreatePolicyVersion → CAN_PRIVESC to mid, high, admin (method_01)
		MERGE (low)-[:IAM_CREATEPOLICYVERSION]->(policy)

		// mid: PutRolePolicy → CAN_PRIVESC to low, high, admin (method_11)
		MERGE (mid)-[:IAM_PUTROLEPOLICY]->(policy)

		// high: UpdateLoginProfile → CAN_PRIVESC to low, mid, admin (method_05)
		MERGE (high)-[:IAM_UPDATELOGINPROFILE]->(admin)
	`, nil)
	require.NoError(t, err, "seed multi-hop graph")

	err = EnrichAWS(ctx, db)
	require.NoError(t, err, "EnrichAWS should succeed")

	t.Run("enrichment_creates_1hop_low_to_admin", func(t *testing.T) {
		result, err := db.Query(ctx,
			`MATCH (a {Arn: 'arn:aws:iam::123456789012:user/low'})-[r:CAN_PRIVESC]->(b {Arn: 'arn:aws:iam::123456789012:role/admin'})
			 RETURN count(r) AS n`, nil)
		require.NoError(t, err)
		n, _ := toInt64(result.Records[0]["n"])
		assert.GreaterOrEqual(t, int(n), 1, "low → admin direct 1-hop via method_01")
	})

	t.Run("enrichment_creates_1hop_mid_to_admin", func(t *testing.T) {
		result, err := db.Query(ctx,
			`MATCH (a {Arn: 'arn:aws:iam::123456789012:role/mid'})-[r:CAN_PRIVESC]->(b {Arn: 'arn:aws:iam::123456789012:role/admin'})
			 RETURN count(r) AS n`, nil)
		require.NoError(t, err)
		n, _ := toInt64(result.Records[0]["n"])
		assert.GreaterOrEqual(t, int(n), 1, "mid → admin direct 1-hop via method_11")
	})

	t.Run("enrichment_creates_principal_to_principal_edges", func(t *testing.T) {
		// Standalone methods fire for ALL other principals; low should have edges to mid and high.
		result, err := db.Query(ctx,
			`MATCH (a {Arn: 'arn:aws:iam::123456789012:user/low'})-[:CAN_PRIVESC]->(b:Principal)
			 WHERE b.Arn <> a.Arn RETURN count(b) AS n`, nil)
		require.NoError(t, err)
		n, _ := toInt64(result.Records[0]["n"])
		assert.GreaterOrEqual(t, int(n), 3,
			"low should have CAN_PRIVESC edges to mid, high, and admin (at least 3 principals)")
	})

	t.Run("no_self_privesc_edges", func(t *testing.T) {
		result, err := db.Query(ctx, `MATCH (a)-[r:CAN_PRIVESC]->(a) RETURN count(r) AS n`, nil)
		require.NoError(t, err)
		n, _ := toInt64(result.Records[0]["n"])
		assert.Equal(t, int64(0), n, "no principal should have a CAN_PRIVESC edge to itself")
	})
}

// TestPrivescAnalysisQuery tests the registered aws/analysis/privesc_paths query
// end-to-end via RunPlatformQuery with controlled CAN_PRIVESC edge scenarios.
func TestPrivescAnalysisQuery(t *testing.T) {
	ctx := context.Background()

	boltURL, cleanup, err := startNeo4jContainer(ctx)
	require.NoError(t, err, "start Neo4j container")
	t.Cleanup(cleanup)

	cfg := graph.NewConfig(boltURL, "", "")
	db, err := adapters.NewNeo4jAdapter(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	// Seed a controlled graph directly with CAN_PRIVESC edges.
	// This tests the analysis query in isolation from enrichment logic.
	_, err = db.Query(ctx, `
		// 1-hop: a1 → admin directly
		CREATE (a1:Principal    {Arn: 'arn:aws:iam::1:user/a1',    _is_admin: false})

		// 2-hop: b1 → b2 → admin (b1 cannot reach admin directly)
		CREATE (b1:Principal    {Arn: 'arn:aws:iam::1:user/b1',    _is_admin: false})
		CREATE (b2:Principal    {Arn: 'arn:aws:iam::1:role/b2',    _is_admin: false})

		// 3-hop: c1 → c2 → c3 → admin
		CREATE (c1:Principal    {Arn: 'arn:aws:iam::1:user/c1',    _is_admin: false})
		CREATE (c2:Principal    {Arn: 'arn:aws:iam::1:role/c2',    _is_admin: false})
		CREATE (c3:Principal    {Arn: 'arn:aws:iam::1:role/c3',    _is_admin: false})

		// >3-hop: d1 → d2 → d3 → d4 → admin (should NOT be found)
		CREATE (d1:Principal    {Arn: 'arn:aws:iam::1:user/d1',    _is_admin: false})
		CREATE (d2:Principal    {Arn: 'arn:aws:iam::1:role/d2',    _is_admin: false})
		CREATE (d3:Principal    {Arn: 'arn:aws:iam::1:role/d3',    _is_admin: false})
		CREATE (d4:Principal    {Arn: 'arn:aws:iam::1:role/d4',    _is_admin: false})

		CREATE (admin:Principal {Arn: 'arn:aws:iam::1:role/admin', _is_admin: true})
		CREATE (admin2:Principal{Arn: 'arn:aws:iam::1:role/admin2',_is_admin: true})

		WITH a1, b1, b2, c1, c2, c3, d1, d2, d3, d4, admin, admin2

		// 1-hop path
		MERGE (a1)-[:CAN_PRIVESC]->(admin)

		// 2-hop path (no direct b1→admin edge)
		MERGE (b1)-[:CAN_PRIVESC]->(b2)
		MERGE (b2)-[:CAN_PRIVESC]->(admin)

		// 3-hop path
		MERGE (c1)-[:CAN_PRIVESC]->(c2)
		MERGE (c2)-[:CAN_PRIVESC]->(c3)
		MERGE (c3)-[:CAN_PRIVESC]->(admin)

		// 4-hop (should NOT appear in results — beyond 1..3 limit)
		MERGE (d1)-[:CAN_PRIVESC]->(d2)
		MERGE (d2)-[:CAN_PRIVESC]->(d3)
		MERGE (d3)-[:CAN_PRIVESC]->(d4)
		MERGE (d4)-[:CAN_PRIVESC]->(admin)

		// admin→admin (should be excluded because attacker._is_admin=true)
		MERGE (admin)-[:CAN_PRIVESC]->(admin2)
	`, nil)
	require.NoError(t, err, "seed analysis query graph")

	// Invoke the registered analysis query (not inline Cypher).
	result, err := RunPlatformQuery(ctx, db, "aws/analysis/privesc_paths", nil)
	require.NoError(t, err, "analysis query should run without error")
	require.NotNil(t, result)

	// Index results by (attacker, hop_count) for assertions.
	type pathKey struct{ attacker string; hops int64 }
	found := map[pathKey]bool{}
	for _, rec := range result.Records {
		attacker, _ := rec["attacker_arn"].(string)
		hops, _ := toInt64(rec["hop_count"])
		found[pathKey{attacker, hops}] = true
		t.Logf("  path: %s → %s (%d hops)", attacker, rec["target_arn"], hops)
	}

	t.Run("1_hop_a1_to_admin", func(t *testing.T) {
		assert.True(t, found[pathKey{"arn:aws:iam::1:user/a1", 1}],
			"a1 should reach admin in 1 hop")
	})

	t.Run("2_hop_b1_to_admin", func(t *testing.T) {
		assert.True(t, found[pathKey{"arn:aws:iam::1:user/b1", 2}],
			"b1 should reach admin in 2 hops via b2")
	})

	t.Run("3_hop_c1_to_admin", func(t *testing.T) {
		assert.True(t, found[pathKey{"arn:aws:iam::1:user/c1", 3}],
			"c1 should reach admin in 3 hops via c2 → c3")
	})

	t.Run("4_hop_d1_not_found", func(t *testing.T) {
		// The analysis query bounds to CAN_PRIVESC*1..3, so hop_count can only be 1–3.
		// Assert d1 never appears as attacker at ANY hop count — not just hop_count=4,
		// which would be a structural no-op since the map never receives keys with hops:4.
		for _, rec := range result.Records {
			attacker, _ := rec["attacker_arn"].(string)
			assert.NotEqual(t, "arn:aws:iam::1:user/d1", attacker,
				"d1's 4-hop path exceeds CAN_PRIVESC*1..3 limit and must not appear at any hop count")
		}
	})

	t.Run("admin_to_admin_excluded", func(t *testing.T) {
		for _, rec := range result.Records {
			attacker, _ := rec["attacker_arn"].(string)
			assert.NotEqual(t, "arn:aws:iam::1:role/admin", attacker,
				"admin principal should never appear as an attacker (filtered by _is_admin=true)")
		}
	})

	t.Run("no_self_loops", func(t *testing.T) {
		for _, rec := range result.Records {
			assert.NotEqual(t, rec["attacker_arn"], rec["target_arn"],
				"attacker and target should never be the same principal")
		}
	})
}

// TestPassRoleServiceFanOutReachesAnalysisQuery is the critical end-to-end proof for the
// Concern B + CodeRabbit scoped-fix: seeds a PassRole+AppRunner scenario where the passed
// role is itself an admin principal, runs EnrichAWS, then verifies the analysis query
// finds a 1-hop path from attacker to that admin role.
//
// With the scoped fix, method_43 creates CAN_PRIVESC(attacker → passed_role). If the passed
// role has _is_admin=true the analysis query reports it immediately as a 1-hop finding.
func TestPassRoleServiceFanOutReachesAnalysisQuery(t *testing.T) {
	ctx := context.Background()

	boltURL, cleanup, err := startNeo4jContainer(ctx)
	require.NoError(t, err)
	t.Cleanup(cleanup)

	cfg := graph.NewConfig(boltURL, "", "")
	db, err := adapters.NewNeo4jAdapter(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	const adminRoleARN = "arn:aws:iam::123:role/admin"

	// The attacker passes an admin IAM role to AppRunner.
	// The passed role is :Principal with _is_admin=true so the scoped CAN_PRIVESC
	// edge points directly to an admin target visible to the analysis query.
	_, err = db.Query(ctx, fmt.Sprintf(`
		CREATE (attacker:Principal {Arn: '%s', _is_admin: false})
		CREATE (adminRole:Principal {Arn: '%s', _is_admin: true})
		CREATE (svc:Resource       {Arn: '%s'})
		WITH attacker, adminRole, svc
		MERGE (attacker)-[:IAM_PASSROLE]->(adminRole)
		MERGE (attacker)-[:APPRUNNER_CREATESERVICE]->(svc)
	`, attackerARN, adminRoleARN, svcResourceARN), nil)
	require.NoError(t, err)

	err = EnrichAWS(ctx, db)
	require.NoError(t, err)

	// The analysis query must find a path: attacker → adminRole (1 hop).
	result, err := RunPlatformQuery(ctx, db, "aws/analysis/privesc_paths", nil)
	require.NoError(t, err)
	require.NotNil(t, result)

	found := false
	for _, rec := range result.Records {
		if rec["attacker_arn"] == attackerARN {
			found = true
			t.Logf("Found: %s → %s (%v hops)", rec["attacker_arn"], rec["target_arn"], rec["hop_count"])
		}
	}
	assert.True(t, found,
		"PassRole+AppRunner attacker must appear in analysis output — "+
			"if this fails, method_43 has regressed: the scoped CAN_PRIVESC edge must point to the passed :Principal role, not a :Resource")
}

// TestPrivescEdgeMetadata verifies that CAN_PRIVESC edges created by enrichment
// methods carry the correct `method` and `severity` property values.
// A wrong property value here would silently pass the TP count assertion in
// TestPrivescQueriesNeo4j but break pathfinding.cloud method-specific FP tests.
func TestPrivescEdgeMetadata(t *testing.T) {
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
		require.NoError(t, err)
	}

	cases := []struct {
		name         string
		queryID      string
		setup        string
		wantMethod   string
		wantSeverity string
	}{
		{
			name:    "method_43_simple_passrole_service",
			queryID: "aws/enrich/privesc/method_43",
			setup: fmt.Sprintf(`
				CREATE (a:Principal {Arn: '%s'})
				CREATE (r:Principal {Arn: '%s'})
				CREATE (s:Resource  {Arn: '%s'})
				WITH a, r, s
				MERGE (a)-[:IAM_PASSROLE]->(r)
				MERGE (a)-[:APPRUNNER_CREATESERVICE]->(s)
			`, attackerARN, roleARN, svcResourceARN),
			wantMethod:   "iam:PassRole + apprunner:CreateService",
			wantSeverity: "high",
		},
		{
			name:    "method_70_stepfunctions",
			queryID: "aws/enrich/privesc/method_70",
			setup: fmt.Sprintf(`
				CREATE (a:Principal {Arn: '%s'})
				CREATE (r:Principal {Arn: '%s'})
				CREATE (s:Resource  {Arn: '%s'})
				WITH a, r, s
				MERGE (a)-[:IAM_PASSROLE]->(r)
				MERGE (a)-[:STATES_CREATESTATEMACHINE]->(s)
			`, attackerARN, roleARN, svcResourceARN),
			wantMethod:   "iam:PassRole + states:CreateStateMachine",
			wantSeverity: "high",
		},
		{
			name:    "method_88_gamelift_compound",
			queryID: "aws/enrich/privesc/method_88",
			setup: fmt.Sprintf(`
				CREATE (a:Principal {Arn: '%s'})
				CREATE (r:Principal {Arn: '%s'})
				CREATE (s:Resource  {Arn: '%s'})
				WITH a, r, s
				MERGE (a)-[:IAM_PASSROLE]->(r)
				MERGE (a)-[:GAMELIFT_CREATEBUILD]->(s)
				MERGE (a)-[:GAMELIFT_CREATEFLEET]->(s)
			`, attackerARN, roleARN, svcResourceARN),
			wantMethod:   "iam:PassRole + gamelift:CreateBuild + gamelift:CreateFleet",
			wantSeverity: "high",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := newAdapter(t)
			clearDB(t, db)

			_, err := db.Query(ctx, tc.setup, nil)
			require.NoError(t, err, "seed graph")

			_, err = RunPlatformQuery(ctx, db, tc.queryID, nil)
			require.NoError(t, err, "run enrichment query")

			// Verify edge goes to the passed role (roleARN), not a generic victim.
			result, err := db.Query(ctx,
				fmt.Sprintf(`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(v {Arn: '%s'})
				             RETURN r.method AS method, r.severity AS severity`, attackerARN, roleARN),
				nil)
			require.NoError(t, err)
			require.Len(t, result.Records, 1,
				"expected exactly 1 CAN_PRIVESC edge from attacker to passed role")

			assert.Equal(t, tc.wantMethod, result.Records[0]["method"],
				"r.method must match the YAML method property — wrong value breaks pathfinding FP tests")
			assert.Equal(t, tc.wantSeverity, result.Records[0]["severity"],
				"r.severity must be set to 'high'")
		})
	}
}

// TestPrivescNegativePermissions verifies that enrichment methods do NOT fire
// when required permissions are absent or incomplete.
// These are the unit-level false-positive guards that complement the Tier 3
// pathfinding.cloud FP tests.
func TestPrivescNegativePermissions(t *testing.T) {
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
		require.NoError(t, err)
	}

	noEdgeQuery := fmt.Sprintf(
		`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->() RETURN count(r) AS n`, attackerARN)

	cases := []struct {
		name    string
		queryID string
		setup   string
		desc    string
	}{
		{
			name:    "method_43_passrole_only_no_service_action",
			queryID: "aws/enrich/privesc/method_43",
			setup: fmt.Sprintf(`
				CREATE (a:Principal {Arn: '%s'})
				CREATE (r:Principal {Arn: '%s'})
				WITH a, r
				MERGE (a)-[:IAM_PASSROLE]->(r)
			`, attackerARN, roleARN),
			desc: "iam:PassRole alone must not trigger method_43 (requires apprunner:CreateService too)",
		},
		{
			name:    "method_43_service_action_only_no_passrole",
			queryID: "aws/enrich/privesc/method_43",
			setup: fmt.Sprintf(`
				CREATE (a:Principal {Arn: '%s'})
				CREATE (s:Resource  {Arn: '%s'})
				WITH a, s
				MERGE (a)-[:APPRUNNER_CREATESERVICE]->(s)
			`, attackerARN, svcResourceARN),
			desc: "apprunner:CreateService alone must not trigger method_43 (requires iam:PassRole too)",
		},
		{
			name:    "method_88_missing_createfleet_action",
			queryID: "aws/enrich/privesc/method_88",
			setup: fmt.Sprintf(`
				CREATE (a:Principal {Arn: '%s'})
				CREATE (r:Principal {Arn: '%s'})
				CREATE (s:Resource  {Arn: '%s'})
				WITH a, r, s
				MERGE (a)-[:IAM_PASSROLE]->(r)
				MERGE (a)-[:GAMELIFT_CREATEBUILD]->(s)
			`, attackerARN, roleARN, svcResourceARN),
			desc: "PassRole+CreateBuild without CreateFleet must not trigger method_88 — compound methods require ALL actions",
		},
		{
			name:    "method_88_missing_createbuild_action",
			queryID: "aws/enrich/privesc/method_88",
			setup: fmt.Sprintf(`
				CREATE (a:Principal {Arn: '%s'})
				CREATE (r:Principal {Arn: '%s'})
				CREATE (s:Resource  {Arn: '%s'})
				WITH a, r, s
				MERGE (a)-[:IAM_PASSROLE]->(r)
				MERGE (a)-[:GAMELIFT_CREATEFLEET]->(s)
			`, attackerARN, roleARN, svcResourceARN),
			desc: "PassRole+CreateFleet without CreateBuild must not trigger method_88",
		},
		{
			name:    "method_43_passrole_to_non_principal_resource",
			queryID: "aws/enrich/privesc/method_43",
			setup: fmt.Sprintf(`
				CREATE (a:Principal {Arn: '%s'})
				CREATE (r:Resource  {Arn: '%s'})
				CREATE (s:Resource  {Arn: '%s'})
				WITH a, r, s
				MERGE (a)-[:IAM_PASSROLE]->(r)
				MERGE (a)-[:APPRUNNER_CREATESERVICE]->(s)
			`, attackerARN, roleARN, svcResourceARN),
			desc: "PassRole targeting a :Resource node (not :Principal) must produce 0 edges — scoped fix only creates CAN_PRIVESC to :Principal targets",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := newAdapter(t)
			clearDB(t, db)

			_, err := db.Query(ctx, tc.setup, nil)
			require.NoError(t, err, "seed graph")

			_, err = RunPlatformQuery(ctx, db, tc.queryID, nil)
			require.NoError(t, err, "enrichment query must not error on incomplete permissions")

			result, err := db.Query(ctx, noEdgeQuery, nil)
			require.NoError(t, err)
			require.Len(t, result.Records, 1)

			n, _ := toInt64(result.Records[0]["n"])
			assert.Equal(t, int64(0), n,
				"FP guard: %s — got %d edge(s), want 0", tc.desc, n)
		})
	}
}

// TestPrivescEnrichAWSIdempotent verifies that running EnrichAWS twice on the
// same graph does not create duplicate CAN_PRIVESC edges.
// Idempotency is guaranteed by MERGE semantics, but this test guards against
// regressions where a query accidentally uses CREATE instead of MERGE.
func TestPrivescEnrichAWSIdempotent(t *testing.T) {
	ctx := context.Background()

	boltURL, cleanup, err := startNeo4jContainer(ctx)
	require.NoError(t, err, "start Neo4j container")
	t.Cleanup(cleanup)

	cfg := graph.NewConfig(boltURL, "", "")
	db, err := adapters.NewNeo4jAdapter(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	_, err = db.Query(ctx, "MATCH (n) DETACH DELETE n", nil)
	require.NoError(t, err)

	// Seed attacker with PassRole + AppRunner (method_43).
	// Role must be :Principal so the scoped query can find it as the victim.
	_, err = db.Query(ctx, fmt.Sprintf(`
		CREATE (a:Principal {Arn: '%s'})
		CREATE (r:Principal {Arn: '%s'})
		CREATE (s:Resource  {Arn: '%s'})
		WITH a, r, s
		MERGE (a)-[:IAM_PASSROLE]->(r)
		MERGE (a)-[:APPRUNNER_CREATESERVICE]->(s)
	`, attackerARN, roleARN, svcResourceARN), nil)
	require.NoError(t, err, "seed graph")

	countEdges := func() int {
		result, err := db.Query(ctx,
			fmt.Sprintf(`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->() RETURN count(r) AS n`, attackerARN),
			nil)
		require.NoError(t, err)
		require.Len(t, result.Records, 1)
		n, _ := toInt64(result.Records[0]["n"])
		return int(n)
	}

	require.NoError(t, EnrichAWS(ctx, db), "first EnrichAWS run")
	countAfterFirst := countEdges()
	require.Greater(t, countAfterFirst, 0, "first run must produce at least 1 CAN_PRIVESC edge")

	require.NoError(t, EnrichAWS(ctx, db), "second EnrichAWS run")
	countAfterSecond := countEdges()

	assert.Equal(t, countAfterFirst, countAfterSecond,
		"EnrichAWS is not idempotent: edge count changed from %d to %d on second run — "+
			"check if any query uses CREATE instead of MERGE",
		countAfterFirst, countAfterSecond)
}

// TestPrivescMultiHopThroughPassRoleMethod verifies that a CAN_PRIVESC edge
// created by a PassRole+service method (method_43) can act as an intermediate
// hop in a chain detected by the aws/analysis/privesc_paths query.
//
// Graph:  attacker --[method_43 scoped]--> intermediate (passed role)
//                  intermediate --[method_01 standalone]--> admin
//
// The key: attacker passes an IAM role (intermediate) that itself has standalone
// IAM escalation paths. The scoped fix ensures intermediate is a reachable
// Principal node in the graph, enabling the 2-hop chain.
func TestPrivescMultiHopThroughPassRoleMethod(t *testing.T) {
	ctx := context.Background()

	boltURL, cleanup, err := startNeo4jContainer(ctx)
	require.NoError(t, err, "start Neo4j container")
	t.Cleanup(cleanup)

	cfg := graph.NewConfig(boltURL, "", "")
	db, err := adapters.NewNeo4jAdapter(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	const (
		interARN  = "arn:aws:iam::123456789012:role/intermediate"
		adminARN  = "arn:aws:iam::123456789012:role/admin"
		policyARN = "arn:aws:iam::123456789012:policy/test-policy"
	)

	// intermediate IS the passed role: attacker passes it via IAM_PASSROLE so
	// method_43 creates attacker → [CAN_PRIVESC] → intermediate (scoped victim).
	// intermediate also has IAM_CREATEPOLICYVERSION so method_01 fans out
	// intermediate → [CAN_PRIVESC] → admin.
	_, err = db.Query(ctx, fmt.Sprintf(`
		CREATE (attacker:Principal    {Arn: '%s', _is_admin: false})
		CREATE (intermediate:Principal{Arn: '%s', _is_admin: false})
		CREATE (admin:Principal       {Arn: '%s', _is_admin: true})
		CREATE (svc:Resource          {Arn: '%s'})
		CREATE (policy:Resource       {Arn: '%s'})
		WITH attacker, intermediate, admin, svc, policy
		MERGE (attacker)-[:IAM_PASSROLE]->(intermediate)
		MERGE (attacker)-[:APPRUNNER_CREATESERVICE]->(svc)
		MERGE (intermediate)-[:IAM_CREATEPOLICYVERSION]->(policy)
	`, attackerARN, interARN, adminARN, svcResourceARN, policyARN), nil)
	require.NoError(t, err, "seed multi-hop graph")

	require.NoError(t, EnrichAWS(ctx, db), "EnrichAWS")

	result, err := RunPlatformQuery(ctx, db, "aws/analysis/privesc_paths", nil)
	require.NoError(t, err)
	require.NotNil(t, result)

	type pathKey struct {
		attacker string
		hops     int64
	}
	found := map[pathKey]bool{}
	for _, rec := range result.Records {
		a, _ := rec["attacker_arn"].(string)
		h, _ := toInt64(rec["hop_count"])
		found[pathKey{a, h}] = true
		t.Logf("  path: %s → %s (%d hops)", a, rec["target_arn"], h)
	}

	t.Run("attacker_1hop_to_intermediate_via_scoped_passrole", func(t *testing.T) {
		// The analysis query looks for paths to admin; the 1-hop path only reaches
		// intermediate which is NOT admin. So attacker should NOT appear at 1 hop
		// (intermediate._is_admin = false means the analysis skips it as the terminal target).
		// Verify attacker DOES have a CAN_PRIVESC edge to intermediate in the raw graph.
		edgeResult, err := db.Query(ctx,
			fmt.Sprintf(`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(v {Arn: '%s'}) RETURN count(r) AS n`,
				attackerARN, interARN), nil)
		require.NoError(t, err)
		n, _ := toInt64(edgeResult.Records[0]["n"])
		assert.GreaterOrEqual(t, int(n), 1,
			"method_43 scoped fix: attacker must have CAN_PRIVESC edge to the passed role (intermediate)")
	})

	t.Run("attacker_2hop_to_admin_via_intermediate", func(t *testing.T) {
		assert.True(t, found[pathKey{attackerARN, 2}],
			"attacker must reach admin in 2 hops: attacker→intermediate (method_43 scoped) → admin (method_01). "+
				"Failure here means the scoped CAN_PRIVESC edge is not traversable as an intermediate hop")
	})

	t.Run("intermediate_1hop_to_admin", func(t *testing.T) {
		assert.True(t, found[pathKey{interARN, 1}],
			"intermediate must reach admin in 1 hop via method_01 (standalone IAM escalation)")
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
