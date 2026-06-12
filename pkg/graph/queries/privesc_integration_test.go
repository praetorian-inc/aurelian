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
	roleARN        = "arn:aws:iam::123456789012:role/target-role"
	svcResourceARN = "arn:aws:lambda:us-east-1:123456789012:function:test"

	// Shared-seed node identifiers (see sharedPrivescSeed). The corrected privesc
	// methods scope their CAN_PRIVESC edge to one of these well-defined targets, so a
	// test asserts the edge lands on the RIGHT node — not just that some edge exists.
	sharedAdminRoleARN = "arn:aws:iam::123456789012:role/admin-target"                   // passed/assumed/HAS_ROLE target
	sharedPrivUserARN  = "arn:aws:iam::123456789012:user/priv-victim"                    // access-key / login-profile target
	sharedWildcardARN  = "arn:aws:batch:us-east-1:123456789012:service"                  // service-wildcard terminate-at-resource
	sharedStackARN     = "arn:aws:cloudformation:us-east-1:123456789012:stack/changeset" // cfn change-set stub
)

// sharedPrivescSeed is ONE "all-guards-satisfied" graph reused by every per-method case in
// TestPrivescQueriesNeo4j instead of 85 bespoke seeds. It seeds, in one account (123456789012):
//
//   - attacker (:User:Principal, NOT admin): member of a privileged group, holding a
//     customer-managed policy attached to itself, and holding EVERY permission edge a privesc
//     method keys off (all on the same `svc`/`policy`/`user` nodes so multi-perm methods that
//     require co-resident actions on one node are satisfied).
//   - adminRole (:Role:Principal, _is_admin): trusts ALL relevant service principals, has an
//     InstanceProfileList, is SSM-enabled, is CAN_ASSUME-reachable from the attacker, and is the
//     IAM_PASSROLE target. It is the correct edge target for new-passrole, trust-backed, and
//     existing-compute (HAS_ROLE) methods.
//   - one :Resource per _resourceType used by an existing-compute method, each HAS_ROLE->adminRole.
//   - privUser (:User:Principal, _is_admin): the scoped target of iam:CreateAccessKey /
//     Create/UpdateLoginProfile, with the paired (DeleteAccessKey / Create<->Update) edge.
//   - privGroup (:Group:Principal, _is_admin) in the attacker's GroupList: self-escalation group target.
//   - wildcard / stack stubs for the service-wildcard and change-set methods.
//
// Hyphenated relationship types (EC2-INSTANCE-CONNECT_*, BEDROCK-AGENTCORE_*, COGNITO-IDENTITY_*,
// EMR-SERVERLESS_*) cannot appear in a Go raw-string literal, so they are seeded separately by
// sharedPrivescHyphenatedSeeds.
func sharedPrivescSeed() string {
	return fmt.Sprintf(`
		CREATE (a:User:Principal {Arn: '%s', _is_admin: false,
			GroupList: ['priv-group'],
			AttachedManagedPolicies: '[{"PolicyArn":"%s"}]'})
		CREATE (adminRole:Role:Principal {Arn: '%s', _is_admin: true, _ssm_enabled: true,
			trusted_services: [
				'ec2.amazonaws.com', 'lambda.amazonaws.com', 'cloudformation.amazonaws.com',
				'datapipeline.amazonaws.com', 'glue.amazonaws.com', 'sagemaker.amazonaws.com',
				'ecs-tasks.amazonaws.com', 'states.amazonaws.com', 'scheduler.amazonaws.com',
				'ssm.amazonaws.com', 'kinesisanalytics.amazonaws.com', 'omics.amazonaws.com',
				'emr-serverless.amazonaws.com', 'gamelift.amazonaws.com', 'braket.amazonaws.com',
				'bedrock-agentcore.amazonaws.com', 'tasks.apprunner.amazonaws.com',
				'amplify.amazonaws.com', 'cognito-identity.amazonaws.com',
				'codebuild.amazonaws.com'
			],
			InstanceProfileList: '[{"Arn":"arn:aws:iam::123456789012:instance-profile/ip"}]'})
		CREATE (privUser:User:Principal {Arn: '%s', _is_admin: true})
		CREATE (privGroup:Group:Principal {Arn: 'arn:aws:iam::123456789012:group/priv-group',
			GroupName: 'priv-group', _is_admin: true})
		CREATE (joinGroup:Group:Principal {Arn: 'arn:aws:iam::123456789012:group/join-group',
			GroupName: 'join-group', _is_admin: true})
		CREATE (policy:Resource {Arn: '%s'})
		CREATE (svc:Resource {Arn: '%s'})
		CREATE (wildcard:Resource {Arn: '%s'})
		CREATE (stack:Resource {Arn: '%s'})
		CREATE (cfnStack:Resource    {_resourceType: 'AWS::CloudFormation::Stack',       Arn: 'arn:aws:cloudformation:us-east-1:123456789012:stack/s'})
		CREATE (cfnStackSet:Resource {_resourceType: 'AWS::CloudFormation::StackSet',    Arn: 'arn:aws:cloudformation:us-east-1:123456789012:stackset/ss'})
		CREATE (cbProject:Resource   {_resourceType: 'AWS::CodeBuild::Project',          Arn: 'arn:aws:codebuild:us-east-1:123456789012:project/p'})
		CREATE (glueEndpoint:Resource{_resourceType: 'AWS::Glue::DevEndpoint',           Arn: 'arn:aws:glue:us-east-1:123456789012:devEndpoint/de'})
		CREATE (glueJob:Resource     {_resourceType: 'AWS::Glue::Job',                   Arn: 'arn:aws:glue:us-east-1:123456789012:job/j'})
		CREATE (appRunner:Resource   {_resourceType: 'AWS::AppRunner::Service',          Arn: 'arn:aws:apprunner:us-east-1:123456789012:service/ar'})
		CREATE (ecsTaskDef:Resource  {_resourceType: 'AWS::ECS::TaskDefinition',         Arn: 'arn:aws:ecs:us-east-1:123456789012:task-definition/td'})
		CREATE (sfnMachine:Resource  {_resourceType: 'AWS::StepFunctions::StateMachine', Arn: 'arn:aws:states:us-east-1:123456789012:stateMachine/sm'})
		CREATE (smNotebook:Resource  {_resourceType: 'AWS::SageMaker::NotebookInstance', Arn: 'arn:aws:sagemaker:us-east-1:123456789012:notebook-instance/nb'})
		CREATE (ec2Instance:Resource {_resourceType: 'AWS::EC2::Instance',               Arn: 'arn:aws:ec2:us-east-1:123456789012:instance/i-1'})
		WITH a, adminRole, privUser, privGroup, joinGroup, policy, svc, wildcard, stack,
			cfnStack, cfnStackSet, cbProject, glueEndpoint, glueJob, appRunner,
			ecsTaskDef, sfnMachine, smNotebook, ec2Instance
		// adminRole reachability: attacker can both pass it and assume it.
		MERGE (a)-[:IAM_PASSROLE]->(adminRole)
		MERGE (a)-[:CAN_ASSUME]->(adminRole)
		// Existing-compute resources all run as the privileged adminRole. svc itself carries
		// HAS_ROLE too, so methods that bind their HAS_ROLE join FROM the permission-edge
		// target (lambda_*, apprunner_update_service, stepfunctions_update) resolve the role.
		MERGE (svc)-[:HAS_ROLE]->(adminRole)
		MERGE (cfnStack)-[:HAS_ROLE]->(adminRole)
		MERGE (cfnStackSet)-[:HAS_ROLE]->(adminRole)
		MERGE (cbProject)-[:HAS_ROLE]->(adminRole)
		MERGE (glueEndpoint)-[:HAS_ROLE]->(adminRole)
		MERGE (glueJob)-[:HAS_ROLE]->(adminRole)
		MERGE (appRunner)-[:HAS_ROLE]->(adminRole)
		MERGE (ecsTaskDef)-[:HAS_ROLE]->(adminRole)
		MERGE (sfnMachine)-[:HAS_ROLE]->(adminRole)
		MERGE (smNotebook)-[:HAS_ROLE]->(adminRole)
		MERGE (ec2Instance)-[:HAS_ROLE]->(adminRole)
		// Self-policy methods: the customer-managed policy is attached to the attacker.
		MERGE (a)-[:IAM_CREATEPOLICYVERSION]->(policy)
		MERGE (a)-[:IAM_SETDEFAULTPOLICYVERSION]->(policy)
		// Trust-backed direct takeover: write a policy onto / rewrite trust of the assumable role.
		MERGE (a)-[:IAM_PUTROLEPOLICY]->(adminRole)
		MERGE (a)-[:IAM_ATTACHROLEPOLICY]->(adminRole)
		MERGE (a)-[:IAM_UPDATEASSUMEROLEPOLICY]->(adminRole)
		// Self-escalation on self/group.
		MERGE (a)-[:IAM_PUTUSERPOLICY]->(a)
		MERGE (a)-[:IAM_ATTACHUSERPOLICY]->(a)
		MERGE (a)-[:IAM_PUTGROUPPOLICY]->(privGroup)
		MERGE (a)-[:IAM_ATTACHGROUPPOLICY]->(privGroup)
		// AddUserToGroup must target a privileged group the attacker is NOT already in.
		MERGE (a)-[:IAM_ADDUSERTOGROUP]->(joinGroup)
		MERGE (a)-[:IAM_CREATESERVICELINKEDROLE]->(svc)
		// Principal-access scoped to a privileged USER (with the paired action on the same user).
		MERGE (a)-[:IAM_CREATEACCESSKEY]->(privUser)
		MERGE (a)-[:IAM_DELETEACCESSKEY]->(privUser)
		MERGE (a)-[:IAM_CREATELOGINPROFILE]->(privUser)
		MERGE (a)-[:IAM_UPDATELOGINPROFILE]->(privUser)
		// sts:AssumeRole (paired with the CAN_ASSUME trust edge above).
		MERGE (a)-[:STS_ASSUMEROLE]->(svc)
		// CloudFormation change-set: both actions on the SAME stub.
		MERGE (a)-[:CLOUDFORMATION_CREATECHANGESET]->(stack)
		MERGE (a)-[:CLOUDFORMATION_EXECUTECHANGESET]->(stack)
		// New-passrole + existing-compute service actions (all on svc unless a method needs a
		// specific _resourceType node, which it reaches via the HAS_ROLE edges above).
		MERGE (a)-[:EC2_RUNINSTANCES]->(svc)
		MERGE (a)-[:EC2_REQUESTSPOTINSTANCES]->(svc)
		MERGE (a)-[:EC2_CREATELAUNCHTEMPLATE]->(svc)
		MERGE (a)-[:EC2_CREATELAUNCHTEMPLATEVERSION]->(svc)
		MERGE (a)-[:EC2_MODIFYLAUNCHTEMPLATE]->(svc)
		MERGE (a)-[:EC2_MODIFYINSTANCEATTRIBUTE]->(svc)
		MERGE (a)-[:EC2_STOPINSTANCES]->(svc)
		MERGE (a)-[:EC2_STARTINSTANCES]->(svc)
		MERGE (a)-[:EC2_REPLACEIAMINSTANCEPROFILEASSOCIATION]->(svc)
		MERGE (a)-[:AUTOSCALING_CREATEAUTOSCALINGGROUP]->(svc)
		MERGE (a)-[:LAMBDA_CREATEFUNCTION]->(svc)
		MERGE (a)-[:LAMBDA_UPDATEFUNCTIONCODE]->(svc)
		MERGE (a)-[:LAMBDA_INVOKEFUNCTION]->(svc)
		MERGE (a)-[:LAMBDA_ADDPERMISSION]->(svc)
		MERGE (a)-[:LAMBDA_CREATEEVENTSOURCEMAPPING]->(svc)
		MERGE (a)-[:CLOUDFORMATION_CREATESTACK]->(svc)
		MERGE (a)-[:CLOUDFORMATION_CREATESTACKSET]->(svc)
		MERGE (a)-[:CLOUDFORMATION_CREATESTACKINSTANCES]->(svc)
		MERGE (a)-[:CLOUDFORMATION_UPDATESTACK]->(svc)
		MERGE (a)-[:CLOUDFORMATION_UPDATESTACKSET]->(svc)
		MERGE (a)-[:CODEBUILD_CREATEPROJECT]->(svc)
		MERGE (a)-[:CODEBUILD_UPDATEPROJECT]->(svc)
		MERGE (a)-[:CODEBUILD_STARTBUILD]->(svc)
		MERGE (a)-[:CODEDEPLOY_CREATEDEPLOYMENT]->(svc)
		MERGE (a)-[:DATAPIPELINE_CREATEPIPELINE]->(svc)
		MERGE (a)-[:DATAPIPELINE_PUTPIPELINEDEFINITION]->(svc)
		MERGE (a)-[:DATAPIPELINE_ACTIVATEPIPELINE]->(svc)
		MERGE (a)-[:GLUE_CREATEJOB]->(svc)
		MERGE (a)-[:GLUE_UPDATEJOB]->(svc)
		MERGE (a)-[:GLUE_STARTJOBRUN]->(svc)
		MERGE (a)-[:GLUE_CREATETRIGGER]->(svc)
		MERGE (a)-[:GLUE_CREATESESSION]->(svc)
		MERGE (a)-[:GLUE_RUNSTATEMENT]->(svc)
		MERGE (a)-[:GLUE_CREATEDEVENDPOINT]->(svc)
		MERGE (a)-[:GLUE_UPDATEDEVENDPOINT]->(svc)
		MERGE (a)-[:SAGEMAKER_CREATENOTEBOOKINSTANCE]->(svc)
		MERGE (a)-[:SAGEMAKER_CREATETRAININGJOB]->(svc)
		MERGE (a)-[:SAGEMAKER_CREATEPROCESSINGJOB]->(svc)
		MERGE (a)-[:SAGEMAKER_CREATEPRESIGNEDNOTEBOOKINSTANCEURL]->(svc)
		MERGE (a)-[:SAGEMAKER_UPDATENOTEBOOKINSTANCELIFECYCLECONFIG]->(svc)
		MERGE (a)-[:ECS_CREATESERVICE]->(svc)
		MERGE (a)-[:ECS_RUNTASK]->(svc)
		MERGE (a)-[:ECS_STARTTASK]->(svc)
		MERGE (a)-[:ECS_EXECUTECOMMAND]->(svc)
		MERGE (a)-[:STATES_CREATESTATEMACHINE]->(svc)
		MERGE (a)-[:STATES_UPDATESTATEMACHINE]->(svc)
		MERGE (a)-[:STATES_STARTEXECUTION]->(svc)
		MERGE (a)-[:SCHEDULER_CREATESCHEDULE]->(svc)
		MERGE (a)-[:SSM_SENDCOMMAND]->(svc)
		MERGE (a)-[:SSM_STARTSESSION]->(svc)
		MERGE (a)-[:SSM_CREATEASSOCIATION]->(svc)
		MERGE (a)-[:SSM_CREATEDOCUMENT]->(svc)
		MERGE (a)-[:SSM_STARTAUTOMATIONEXECUTION]->(svc)
		MERGE (a)-[:KINESISANALYTICS_CREATEAPPLICATION]->(svc)
		MERGE (a)-[:KINESISANALYTICS_STARTAPPLICATION]->(svc)
		MERGE (a)-[:OMICS_CREATEWORKFLOW]->(svc)
		MERGE (a)-[:OMICS_STARTRUN]->(svc)
		MERGE (a)-[:ELASTICMAPREDUCE_RUNJOBFLOW]->(svc)
		MERGE (a)-[:GAMELIFT_CREATEBUILD]->(svc)
		MERGE (a)-[:GAMELIFT_CREATEFLEET]->(svc)
		MERGE (a)-[:BRAKET_CREATEJOB]->(svc)
		MERGE (a)-[:APPRUNNER_CREATESERVICE]->(svc)
		MERGE (a)-[:APPRUNNER_UPDATESERVICE]->(svc)
		MERGE (a)-[:AMPLIFY_CREATEAPP]->(svc)
		MERGE (a)-[:AMPLIFY_CREATEBRANCH]->(svc)
		MERGE (a)-[:AMPLIFY_STARTJOB]->(svc)
		MERGE (a)-[:IMAGEBUILDER_CREATEINFRASTRUCTURECONFIGURATION]->(svc)
		MERGE (a)-[:IMAGEBUILDER_CREATEIMAGE]->(svc)
		MERGE (a)-[:BATCH_REGISTERJOBDEFINITION]->(svc)
		MERGE (a)-[:BATCH_SUBMITJOB]->(wildcard)
		MERGE (a)-[:CODESTAR_CREATEPROJECT]->(wildcard)
	`, attackerARN, "arn:aws:iam::123456789012:policy/custom",
		sharedAdminRoleARN, sharedPrivUserARN, "arn:aws:iam::123456789012:policy/custom",
		svcResourceARN, sharedWildcardARN, sharedStackARN)
}

// sharedPrivescHyphenatedSeeds returns the MERGE statements for relationship types that
// contain hyphens (illegal in a Go raw-string literal), bound to the shared-seed attacker.
func sharedPrivescHyphenatedSeeds() []string {
	mk := func(relType, targetARN string) string {
		return fmt.Sprintf("MATCH (a {Arn: '%s'}), (t {Arn: '%s'}) MERGE (a)-[:`%s`]->(t)",
			attackerARN, targetARN, relType)
	}
	return []string{
		mk("EC2-INSTANCE-CONNECT_SENDSSHPUBLICKEY", svcResourceARN),
		mk("BEDROCK-AGENTCORE_CREATECODEINTERPRETER", svcResourceARN),
		mk("BEDROCK-AGENTCORE_STARTCODEINTERPRETERSESSION", svcResourceARN),
		mk("BEDROCK-AGENTCORE_INVOKESESSION", sharedWildcardARN),
		mk("COGNITO-IDENTITY_SETIDENTITYPOOLROLES", svcResourceARN),
		mk("COGNITO-IDENTITY_GETID", svcResourceARN),
		mk("COGNITO-IDENTITY_GETCREDENTIALSFORIDENTITY", svcResourceARN),
		mk("EMR-SERVERLESS_CREATEAPPLICATION", svcResourceARN),
		mk("EMR-SERVERLESS_STARTJOBRUN", svcResourceARN),
	}
}

// privescTarget identifies the node a corrected method's CAN_PRIVESC edge must terminate at.
type privescTarget int

const (
	targetSelfLoop  privescTarget = iota // self-escalation: attacker -> attacker
	targetAdminRole                      // new-passrole / trust-backed / existing-compute -> the privileged role
	targetPrivUser                       // principal-access -> the privileged user node
	targetWildcard                       // service-wildcard methods -> the service resource stub
	targetStack                          // cloudformation_changeset -> the same stack stub
	targetNone                           // method intentionally emits no edge (e.g. SLR)
)

// sharedSeedCase asserts that running queryID against the shared seed emits a correctly-scoped
// CAN_PRIVESC edge to the target node (and, for targetNone, emits none).
type sharedSeedCase struct {
	queryID string
	target  privescTarget
}

func (tc sharedSeedCase) verify() (cypher string, wantZero bool) {
	dst := func(arn string) string {
		return fmt.Sprintf(
			`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(v {Arn: '%s'}) RETURN count(r) AS n`,
			attackerARN, arn)
	}
	switch tc.target {
	case targetSelfLoop:
		return fmt.Sprintf(`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(a) RETURN count(r) AS n`, attackerARN), false
	case targetAdminRole:
		return dst(sharedAdminRoleARN), false
	case targetPrivUser:
		return dst(sharedPrivUserARN), false
	case targetWildcard:
		return dst(sharedWildcardARN), false
	case targetStack:
		return dst(sharedStackARN), false
	default: // targetNone
		return fmt.Sprintf(`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->() RETURN count(r) AS n`, attackerARN), true
	}
}

// allSharedSeedCases declares the expected edge target for every privesc method. Each method
// runs against the same sharedPrivescSeed; the target encodes the correctly-scoped destination
// the cartesian-fix + structural guards must produce (self-loop / passed role / reached role /
// resource role / service stub) — and proves no method emits to an unexpected node.
func allSharedSeedCases() []sharedSeedCase {
	const p = "aws/enrich/privesc/"
	return []sharedSeedCase{
		// --- Self-escalation (target = attacker self-loop) ---
		{p + "iam_create_policy_version", targetSelfLoop},
		{p + "iam_set_default_policy_version", targetSelfLoop},
		{p + "iam_put_user_policy", targetSelfLoop},
		{p + "iam_attach_user_policy", targetSelfLoop},
		{p + "iam_put_group_policy", targetSelfLoop},
		{p + "iam_attach_group_policy", targetSelfLoop},
		{p + "iam_add_user_to_group", targetSelfLoop},
		{p + "ssm_createdocument_startautomation", targetSelfLoop},

		// --- Intentional no-op (created SLR is not a usable escalation in the graph) ---
		{p + "iam_create_service_linked_role", targetNone},

		// --- Trust-backed direct takeover / principal-access ROLE target (-> adminRole) ---
		{p + "iam_put_role_policy", targetAdminRole},
		{p + "iam_attach_role_policy", targetAdminRole},
		{p + "iam_update_assume_role_policy", targetAdminRole},
		{p + "sts_assume_role", targetAdminRole},
		{p + "passrole_modify_policy", targetAdminRole},
		{p + "update_assume_role_passrole_service", targetAdminRole},

		// --- Principal-access scoped to a privileged USER (-> privUser) ---
		{p + "iam_create_access_key", targetPrivUser},
		{p + "iam_create_login_profile", targetPrivUser},
		{p + "iam_update_login_profile", targetPrivUser},

		// --- New-passrole (-> passed adminRole) ---
		{p + "iam_pass_role_ec2", targetAdminRole},
		{p + "iam_pass_role_lambda", targetAdminRole},
		{p + "iam_pass_role_cloudformation", targetAdminRole},
		{p + "iam_pass_role_datapipeline", targetAdminRole},
		{p + "iam_pass_role_glue", targetAdminRole},
		{p + "iam_pass_role_sagemaker", targetAdminRole},
		{p + "ec2_request_spot_instances", targetAdminRole},
		{p + "ec2_replace_instance_profile", targetAdminRole},
		{p + "autoscaling_launch_template", targetAdminRole},
		{p + "apprunner_create_service", targetAdminRole},
		{p + "batch_passrole", targetAdminRole},
		{p + "braket_create_job", targetAdminRole},
		{p + "cloudformation_create_stackset", targetAdminRole},
		{p + "codebuild_create_project", targetAdminRole},
		{p + "codebuild_update_project", targetAdminRole},
		{p + "cognito_set_identity_pool_roles", targetAdminRole},
		{p + "ecs_create_service", targetAdminRole},
		{p + "ecs_passrole_runtask", targetAdminRole},
		{p + "ecs_start_task", targetAdminRole},
		{p + "emr_run_job_flow", targetAdminRole},
		{p + "emr_serverless", targetAdminRole},
		{p + "emr_serverless_startjobrun", targetAdminRole},
		{p + "gamelift_create_fleet", targetAdminRole},
		{p + "gamelift_createbuild_createfleet", targetAdminRole},
		{p + "glue_create_dev_endpoint", targetAdminRole},
		{p + "glue_create_session", targetAdminRole},
		{p + "glue_createjob_createtrigger", targetAdminRole},
		{p + "glue_createjob_startjobrun", targetAdminRole},
		{p + "glue_createsession_runstatement", targetAdminRole},
		{p + "imagebuilder_create_pipeline", targetAdminRole},
		{p + "imagebuilder_createimage", targetAdminRole},
		{p + "kinesis_analytics", targetAdminRole},
		{p + "kinesisanalytics_startapplication", targetAdminRole},
		{p + "lambda_passrole_createfunction_addpermission", targetAdminRole},
		{p + "omics_create_workflow", targetAdminRole},
		{p + "omics_startrun", targetAdminRole},
		{p + "sagemaker_processing_job", targetAdminRole},
		{p + "sagemaker_training_job", targetAdminRole},
		{p + "scheduler_create_schedule", targetAdminRole},
		{p + "ssm_start_automation", targetAdminRole},
		{p + "stepfunctions_create", targetAdminRole},
		{p + "stepfunctions_create_startexecution", targetAdminRole},
		{p + "amplify_create_app", targetAdminRole},
		{p + "bedrock_create_code_interpreter", targetAdminRole},

		// --- Existing-compute via HAS_ROLE (-> the resource's adminRole) ---
		{p + "lambda_update_function_code", targetAdminRole},
		{p + "lambda_updatecode_invoke", targetAdminRole},
		{p + "lambda_add_permission", targetAdminRole},
		{p + "lambda_create_event_source_mapping", targetAdminRole},
		{p + "cloudformation_update_stack", targetAdminRole},
		{p + "cloudformation_update_stackset", targetAdminRole},
		{p + "codebuild_start_build", targetAdminRole},
		{p + "codedeploy_create_deployment", targetAdminRole},
		{p + "apprunner_update_service", targetAdminRole},
		{p + "ecs_execute_command", targetAdminRole},
		{p + "stepfunctions_update", targetAdminRole},
		{p + "glue_update_dev_endpoint", targetAdminRole},
		{p + "glue_update_job", targetAdminRole},
		{p + "glue_updatejob_startjobrun", targetAdminRole},
		{p + "glue_updatejob_createtrigger", targetAdminRole},
		{p + "sagemaker_lifecycle_config", targetAdminRole},
		{p + "sagemaker_presigned_url", targetAdminRole},
		{p + "ssm_send_command", targetAdminRole},
		{p + "ssm_start_session", targetAdminRole},
		{p + "ec2_instance_connect", targetAdminRole},
		{p + "ec2_modify_instance_attribute", targetAdminRole},
		{p + "ec2_ssm_association", targetAdminRole},
		{p + "ec2_launch_template_version", targetAdminRole},

		// --- Multi-perm same stub / service-wildcard terminate-at-resource ---
		{p + "cloudformation_changeset", targetStack},
		{p + "batch_submit_job", targetWildcard},
		{p + "bedrock_access_code_interpreter", targetWildcard},
		// codestar_create_project now constrains the permission target to :Principal; the
		// seeded CODESTAR_CREATEPROJECT edge points at the wildcard :Resource stub, which is
		// not a Principal, so the method correctly emits NO edge (matches its description:
		// no graph target until a CodeStar resource->role enricher lands).
		{p + "codestar_create_project", targetNone},
	}
}

// TestPrivescQueriesNeo4j verifies every privesc enrichment query creates a
// correctly-scoped CAN_PRIVESC edge under valid conditions. It seeds ONE shared
// "all-guards-satisfied" graph (sharedPrivescSeed) and runs each method against a fresh
// copy of it, asserting the edge lands on the method's correct target (self-loop / passed
// role / reached role / resource role / service stub) per allSharedSeedCases — not just
// that some edge exists. Requires a Neo4j container (testcontainers).
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

	seed := func(t *testing.T, db graph.GraphDatabase) {
		t.Helper()
		_, err := db.Query(ctx, "MATCH (n) DETACH DELETE n", nil)
		require.NoError(t, err, "clear graph for test isolation")
		_, err = db.Query(ctx, sharedPrivescSeed(), nil)
		require.NoError(t, err, "seed shared privesc graph")
		for _, h := range sharedPrivescHyphenatedSeeds() {
			_, err = db.Query(ctx, h, nil)
			require.NoError(t, err, "seed hyphenated relationship type")
		}
	}

	runCase := func(t *testing.T, tc sharedSeedCase) {
		t.Helper()
		db := newAdapter(t)
		seed(t, db)

		_, err = RunPlatformQuery(ctx, db, tc.queryID, nil)
		require.NoError(t, err, "run enrichment query %s", tc.queryID)

		verify, wantZero := tc.verify()
		result, err := db.Query(ctx, verify, nil)
		require.NoError(t, err, "verify CAN_PRIVESC for %s", tc.queryID)

		require.Len(t, result.Records, 1, "verify query should return exactly one row")
		count, ok := toInt64(result.Records[0]["n"])
		require.True(t, ok, "count should be numeric, got %T", result.Records[0]["n"])

		if wantZero {
			assert.Equal(t, int64(0), count,
				"method %s must emit NO CAN_PRIVESC edge (intentional no-op), got %d", tc.queryID, count)
			return
		}
		assert.GreaterOrEqual(t, int(count), 1,
			"method %s: expected a correctly-scoped CAN_PRIVESC edge to its target, got %d",
			tc.queryID, count)

		// Tighten: the method must NOT fan out to any OTHER principal target beyond its
		// scoped one (the cartesian-bug signature). Self-loop methods are exempt (their
		// only target IS the attacker).
		if tc.target != targetSelfLoop {
			fanResult, err := db.Query(ctx, fmt.Sprintf(
				`MATCH (a {Arn: '%s'})-[:CAN_PRIVESC]->(b) RETURN count(DISTINCT b) AS n`, attackerARN), nil)
			require.NoError(t, err)
			fanout, _ := toInt64(fanResult.Records[0]["n"])
			assert.LessOrEqual(t, fanout, int64(1),
				"method %s must reach exactly one scoped target, not fan out (reached %d distinct nodes)",
				tc.queryID, fanout)
		}
	}

	for _, tc := range allSharedSeedCases() {
		t.Run(tc.queryID, func(t *testing.T) {
			runCase(t, tc)
		})
	}
}

// TestEnrichAWSPrivescEndToEnd runs the FULL EnrichAWS pipeline (all enrichers + all methods)
// over the shared all-guards-satisfied graph and verifies the corrected end-to-end behavior:
// the passed/assumed/HAS_ROLE methods all converge onto the single privileged role target
// (MERGE dedups them into one edge), and no method fans out to an unrelated principal.
func TestEnrichAWSPrivescEndToEnd(t *testing.T) {
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
	_, err = db.Query(ctx, sharedPrivescSeed(), nil)
	require.NoError(t, err, "seed shared privesc graph")
	for _, h := range sharedPrivescHyphenatedSeeds() {
		_, err = db.Query(ctx, h, nil)
		require.NoError(t, err, "seed hyphenated relationship type")
	}

	// Add bystander principals the OLD cartesian fan-out would have reached.
	_, err = db.Query(ctx, `
		UNWIND range(1, 10) AS i
		CREATE (:Principal {Arn: 'arn:aws:iam::123456789012:user/bystander-' + toString(i), _is_admin: false})
	`, nil)
	require.NoError(t, err, "seed bystander population")

	// Run the full enrichment pipeline (enrichers populate _is_admin/_is_privileged/trust/
	// _ssm_enabled/HAS_ROLE; methods then emit CAN_PRIVESC).
	err = EnrichAWS(ctx, db)
	require.NoError(t, err, "EnrichAWS should succeed")

	// Corrected behavior: the privileged role is the convergent target of every passed/
	// assumed/HAS_ROLE method, so it carries at least one CAN_PRIVESC edge.
	result, err := db.Query(ctx,
		fmt.Sprintf(`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(v {Arn: '%s'}) RETURN count(r) AS n`, attackerARN, sharedAdminRoleARN),
		nil)
	require.NoError(t, err)
	require.Len(t, result.Records, 1)
	n, _ := toInt64(result.Records[0]["n"])
	t.Logf("CAN_PRIVESC edges attacker→admin role: %d", n)
	assert.GreaterOrEqual(t, int(n), 1, "enrichment should produce a CAN_PRIVESC edge to the privileged role")

	// No method may fan out to the bystander population (the cartesian-bug signature).
	fanResult, err := db.Query(ctx, fmt.Sprintf(`
		MATCH (a {Arn: '%s'})-[:CAN_PRIVESC]->(b)
		WHERE b.Arn CONTAINS 'bystander-' RETURN count(DISTINCT b) AS n`, attackerARN), nil)
	require.NoError(t, err)
	fanout, _ := toInt64(fanResult.Records[0]["n"])
	assert.Equal(t, int64(0), fanout,
		"no privesc method may emit CAN_PRIVESC to an unrelated bystander principal")
}

// TestPrivescMultiHopPaths verifies that EnrichAWS produces CAN_PRIVESC edges that form real
// principal-to-principal chains detectable by the analysis query, using the CORRECTED
// (scoped) method behavior — no method fans out to every principal.
//
// Chain: mid --[iam_put_role_policy: CAN_ASSUME + PutRolePolicy on the SAME role]--> admin.
// low self-escalates via iam_create_policy_version (a self-loop), which must NOT fan out.
func TestPrivescMultiHopPaths(t *testing.T) {
	ctx := context.Background()

	boltURL, cleanup, err := startNeo4jContainer(ctx)
	require.NoError(t, err, "start Neo4j container")
	t.Cleanup(cleanup)

	cfg := graph.NewConfig(boltURL, "", "")
	db, err := adapters.NewNeo4jAdapter(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	_, err = db.Query(ctx, `
		CREATE (low:Principal  {Arn: 'arn:aws:iam::123456789012:user/low',  _is_admin: false,
			AttachedManagedPolicies: '[{"PolicyArn":"arn:aws:iam::123456789012:policy/p"}]'})
		CREATE (mid:Role:Principal  {Arn: 'arn:aws:iam::123456789012:role/mid',  _is_admin: false})
		CREATE (admin:Role:Principal{Arn: 'arn:aws:iam::123456789012:role/admin',_is_admin: true})
		CREATE (policy:Resource{Arn: 'arn:aws:iam::123456789012:policy/p'})
		WITH low, mid, admin, policy

		// low: CreatePolicyVersion on a customer-managed policy attached to itself
		//      → SELF-LOOP CAN_PRIVESC(low → low) (corrected self-escalation, no fan-out).
		MERGE (low)-[:IAM_CREATEPOLICYVERSION]->(policy)

		// mid: trust-backed direct takeover of admin — mid can assume admin AND write an
		//      inline policy onto it (iam_put_role_policy, corrected) → CAN_PRIVESC(mid → admin).
		MERGE (mid)-[:CAN_ASSUME]->(admin)
		MERGE (mid)-[:IAM_PUTROLEPOLICY]->(admin)
	`, nil)
	require.NoError(t, err, "seed multi-hop graph")

	err = EnrichAWS(ctx, db)
	require.NoError(t, err, "EnrichAWS should succeed")

	t.Run("self_escalation_low_self_loop_via_create_policy_version", func(t *testing.T) {
		result, err := db.Query(ctx,
			`MATCH (a {Arn: 'arn:aws:iam::123456789012:user/low'})-[r:CAN_PRIVESC]->(a)
			 RETURN count(r) AS n`, nil)
		require.NoError(t, err)
		n, _ := toInt64(result.Records[0]["n"])
		assert.GreaterOrEqual(t, int(n), 1,
			"low → low self-loop via iam_create_policy_version (corrected self-escalation)")
	})

	t.Run("create_policy_version_no_fanout_to_other_principals", func(t *testing.T) {
		// low's only escalation perm is CreatePolicyVersion, which self-loops; it must
		// NOT fan out to mid/admin.
		result, err := db.Query(ctx,
			`MATCH (a {Arn: 'arn:aws:iam::123456789012:user/low'})-[:CAN_PRIVESC]->(b:Principal)
			 WHERE b.Arn <> a.Arn RETURN count(b) AS n`, nil)
		require.NoError(t, err)
		n, _ := toInt64(result.Records[0]["n"])
		assert.Equal(t, int64(0), n,
			"low must NOT fan out to other principals — iam_create_policy_version self-loops")
	})

	t.Run("enrichment_creates_1hop_mid_to_admin", func(t *testing.T) {
		result, err := db.Query(ctx,
			`MATCH (a {Arn: 'arn:aws:iam::123456789012:role/mid'})-[r:CAN_PRIVESC]->(b {Arn: 'arn:aws:iam::123456789012:role/admin'})
			 RETURN count(r) AS n`, nil)
		require.NoError(t, err)
		n, _ := toInt64(result.Records[0]["n"])
		assert.GreaterOrEqual(t, int(n), 1,
			"mid → admin direct 1-hop via iam_put_role_policy (trust-backed: CAN_ASSUME + PutRolePolicy on admin)")
	})

	t.Run("mid_does_not_fan_out", func(t *testing.T) {
		// mid's only assumable+writable role is admin; it must not reach any other principal.
		result, err := db.Query(ctx,
			`MATCH (a {Arn: 'arn:aws:iam::123456789012:role/mid'})-[:CAN_PRIVESC]->(b:Principal)
			 RETURN count(DISTINCT b) AS n`, nil)
		require.NoError(t, err)
		n, _ := toInt64(result.Records[0]["n"])
		assert.LessOrEqual(t, n, int64(1),
			"mid must reach only the one assumable/writable role (admin), not fan out")
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
	type pathKey struct {
		attacker string
		hops     int64
	}
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
// With the scoped fix, apprunner_create_service creates CAN_PRIVESC(attacker → passed_role). If the passed
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

	const adminRoleARN = "arn:aws:iam::123456789012:role/admin"

	// The attacker passes an admin IAM role to AppRunner. The passed role is _is_admin and
	// trusts App Runner so the scoped CAN_PRIVESC edge points directly to an admin target
	// visible to the analysis query.
	_, err = db.Query(ctx, fmt.Sprintf(`
		CREATE (attacker:Principal {Arn: '%s', _is_admin: false})
		CREATE (adminRole:Role:Principal {Arn: '%s', _is_admin: true,
			trusted_services: ['tasks.apprunner.amazonaws.com']})
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
			"if this fails, apprunner_create_service has regressed: the scoped CAN_PRIVESC edge must point to the passed :Principal role, not a :Resource")
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
			name:    "apprunner_simple_passrole_service",
			queryID: "aws/enrich/privesc/apprunner_create_service",
			setup: fmt.Sprintf(`
				CREATE (a:Principal {Arn: '%s'})
				CREATE (r:Role:Principal {Arn: '%s', _is_admin: true,
					trusted_services: ['tasks.apprunner.amazonaws.com']})
				CREATE (s:Resource  {Arn: '%s'})
				WITH a, r, s
				MERGE (a)-[:IAM_PASSROLE]->(r)
				MERGE (a)-[:APPRUNNER_CREATESERVICE]->(s)
			`, attackerARN, roleARN, svcResourceARN),
			wantMethod:   "iam:PassRole + apprunner:CreateService",
			wantSeverity: "high",
		},
		{
			name:    "stepfunctions_create_passrole_service",
			queryID: "aws/enrich/privesc/stepfunctions_create",
			setup: fmt.Sprintf(`
				CREATE (a:Principal {Arn: '%s'})
				CREATE (r:Role:Principal {Arn: '%s', _is_admin: true,
					trusted_services: ['states.amazonaws.com']})
				CREATE (s:Resource  {Arn: '%s'})
				WITH a, r, s
				MERGE (a)-[:IAM_PASSROLE]->(r)
				MERGE (a)-[:STATES_CREATESTATEMACHINE]->(s)
			`, attackerARN, roleARN, svcResourceARN),
			wantMethod:   "iam:PassRole + states:CreateStateMachine",
			wantSeverity: "high",
		},
		{
			name:    "gamelift_compound",
			queryID: "aws/enrich/privesc/gamelift_createbuild_createfleet",
			setup: fmt.Sprintf(`
				CREATE (a:Principal {Arn: '%s'})
				CREATE (r:Role:Principal {Arn: '%s', _is_admin: true,
					trusted_services: ['gamelift.amazonaws.com'],
					InstanceProfileList: '[{"Arn":"arn:aws:iam::123456789012:instance-profile/ip"}]'})
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
			name:    "apprunner_passrole_only_no_service_action",
			queryID: "aws/enrich/privesc/apprunner_create_service",
			setup: fmt.Sprintf(`
				CREATE (a:Principal {Arn: '%s'})
				CREATE (r:Role:Principal {Arn: '%s', _is_admin: true,
					trusted_services: ['tasks.apprunner.amazonaws.com']})
				WITH a, r
				MERGE (a)-[:IAM_PASSROLE]->(r)
			`, attackerARN, roleARN),
			desc: "iam:PassRole alone (role trusts App Runner + privileged) must not trigger apprunner_create_service — the missing apprunner:CreateService is the sole rejection",
		},
		{
			name:    "apprunner_service_action_only_no_passrole",
			queryID: "aws/enrich/privesc/apprunner_create_service",
			setup: fmt.Sprintf(`
				CREATE (a:Principal {Arn: '%s'})
				CREATE (s:Resource  {Arn: '%s'})
				WITH a, s
				MERGE (a)-[:APPRUNNER_CREATESERVICE]->(s)
			`, attackerARN, svcResourceARN),
			desc: "apprunner:CreateService alone must not trigger apprunner_create_service (requires iam:PassRole too)",
		},
		{
			name:    "gamelift_missing_createfleet_action",
			queryID: "aws/enrich/privesc/gamelift_createbuild_createfleet",
			setup: fmt.Sprintf(`
				CREATE (a:Principal {Arn: '%s'})
				CREATE (r:Role:Principal {Arn: '%s', _is_admin: true,
					trusted_services: ['gamelift.amazonaws.com'],
					InstanceProfileList: '[{"Arn":"arn:aws:iam::123456789012:instance-profile/ip"}]'})
				CREATE (s:Resource  {Arn: '%s'})
				WITH a, r, s
				MERGE (a)-[:IAM_PASSROLE]->(r)
				MERGE (a)-[:GAMELIFT_CREATEBUILD]->(s)
			`, attackerARN, roleARN, svcResourceARN),
			desc: "PassRole+CreateBuild (role trusts GameLift + privileged) without CreateFleet must not trigger gamelift_createbuild_createfleet — the missing CreateFleet is the sole rejection",
		},
		{
			name:    "gamelift_missing_createbuild_action",
			queryID: "aws/enrich/privesc/gamelift_createbuild_createfleet",
			setup: fmt.Sprintf(`
				CREATE (a:Principal {Arn: '%s'})
				CREATE (r:Role:Principal {Arn: '%s', _is_admin: true,
					trusted_services: ['gamelift.amazonaws.com'],
					InstanceProfileList: '[{"Arn":"arn:aws:iam::123456789012:instance-profile/ip"}]'})
				CREATE (s:Resource  {Arn: '%s'})
				WITH a, r, s
				MERGE (a)-[:IAM_PASSROLE]->(r)
				MERGE (a)-[:GAMELIFT_CREATEFLEET]->(s)
			`, attackerARN, roleARN, svcResourceARN),
			desc: "PassRole+CreateFleet (role trusts GameLift + privileged) without CreateBuild must not trigger gamelift_createbuild_createfleet — the missing CreateBuild is the sole rejection",
		},
		{
			name:    "apprunner_passrole_to_non_principal_resource",
			queryID: "aws/enrich/privesc/apprunner_create_service",
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
		// amplify_create_app (Amplify 3-action): missing one of three required service actions
		{
			name:    "amplify_missing_startjob_action",
			queryID: "aws/enrich/privesc/amplify_create_app",
			setup: fmt.Sprintf(`
				CREATE (a:Principal {Arn: '%s'})
				CREATE (r:Role:Principal {Arn: '%s', _is_admin: true,
					trusted_services: ['amplify.amazonaws.com']})
				CREATE (s:Resource  {Arn: '%s'})
				WITH a, r, s
				MERGE (a)-[:IAM_PASSROLE]->(r)
				MERGE (a)-[:AMPLIFY_CREATEAPP]->(s)
				MERGE (a)-[:AMPLIFY_CREATEBRANCH]->(s)
			`, attackerARN, roleARN, svcResourceARN),
			desc: "amplify_create_app requires all 3 Amplify actions (role trusts Amplify + privileged) — the missing StartJob is the sole rejection",
		},
		// ssm_createdocument_startautomation is a self-escalation: it runs an attacker-authored
		// automation document under the attacker's OWN identity, so both actions are required on
		// the attacker (via EXISTS) but need NOT target the same resource (creating a document
		// and running an automation are distinct resources). The FP guard is therefore the
		// missing-action case: holding only CreateDocument must produce no edge.
		{
			name:    "ssm_createdocument_only_no_startautomation",
			queryID: "aws/enrich/privesc/ssm_createdocument_startautomation",
			setup: fmt.Sprintf(`
				CREATE (a:Principal {Arn: '%s', _is_admin: false})
				CREATE (doc:Resource {Arn: 'arn:aws:ssm:us-east-1:123:document/my-doc'})
				WITH a, doc
				MERGE (a)-[:SSM_CREATEDOCUMENT]->(doc)
			`, attackerARN),
			desc: "ssm_createdocument_startautomation must not fire with only ssm:CreateDocument — both actions are required",
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

	// Seed attacker with PassRole + AppRunner (apprunner_create_service). The passed role
	// must trust App Runner and be privileged to satisfy the corrected guards.
	_, err = db.Query(ctx, fmt.Sprintf(`
		CREATE (a:Principal {Arn: '%s', _is_admin: false})
		CREATE (r:Role:Principal {Arn: '%s', _is_admin: true,
			trusted_services: ['tasks.apprunner.amazonaws.com']})
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

// TestPrivescMultiHopThroughPassRoleMethod verifies that a CAN_PRIVESC edge created by a
// PassRole+service method (apprunner_create_service) can act as an intermediate hop in a
// chain detected by the aws/analysis/privesc_paths query.
//
// Graph:  attacker --[apprunner_create_service scoped]--> intermediate (passed App-Runner role)
//
//	intermediate --[iam_put_role_policy: CAN_ASSUME + PutRolePolicy on admin]--> admin
//
// The scoped fix ensures intermediate is a reachable :Principal node, enabling the 2-hop chain.
// The intermediate→admin hop uses the CORRECTED iam_put_role_policy (trust-backed: a CAN_ASSUME
// edge plus PutRolePolicy on the SAME admin role), not the old fan-out.
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
		interARN = "arn:aws:iam::123456789012:role/intermediate"
		adminARN = "arn:aws:iam::123456789012:role/admin"
	)

	// intermediate IS the passed role: it trusts App Runner and is privileged, so
	// apprunner_create_service creates attacker → [CAN_PRIVESC] → intermediate (scoped victim).
	// intermediate can assume admin AND write a policy onto it, so iam_put_role_policy
	// creates intermediate → [CAN_PRIVESC] → admin (corrected trust-backed takeover).
	_, err = db.Query(ctx, fmt.Sprintf(`
		CREATE (attacker:Principal      {Arn: '%s', _is_admin: false})
		CREATE (intermediate:Role:Principal {Arn: '%s', _is_admin: false,
			trusted_services: ['tasks.apprunner.amazonaws.com']})
		CREATE (admin:Role:Principal    {Arn: '%s', _is_admin: true})
		CREATE (svc:Resource            {Arn: '%s'})
		WITH attacker, intermediate, admin, svc
		MERGE (attacker)-[:IAM_PASSROLE]->(intermediate)
		MERGE (attacker)-[:APPRUNNER_CREATESERVICE]->(svc)
		MERGE (intermediate)-[:CAN_ASSUME]->(admin)
		MERGE (intermediate)-[:IAM_PUTROLEPOLICY]->(admin)
	`, attackerARN, interARN, adminARN, svcResourceARN), nil)
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
			"apprunner_create_service scoped fix: attacker must have CAN_PRIVESC edge to the passed role (intermediate)")
	})

	t.Run("attacker_2hop_to_admin_via_intermediate", func(t *testing.T) {
		assert.True(t, found[pathKey{attackerARN, 2}],
			"attacker must reach admin in 2 hops: attacker→intermediate (apprunner_create_service scoped) → admin (iam_put_role_policy). "+
				"Failure here means the scoped CAN_PRIVESC edge is not traversable as an intermediate hop")
	})

	t.Run("intermediate_1hop_to_admin", func(t *testing.T) {
		assert.True(t, found[pathKey{interARN, 1}],
			"intermediate must reach admin in 1 hop via iam_put_role_policy (trust-backed: CAN_ASSUME + PutRolePolicy on admin)")
	})
}

// TestPrivescEnrichersPopulate verifies the foundational Phase-2 enrichers actually
// populate the guard inputs the corrected methods depend on:
//   - set_admin_administrator_access sets _is_admin via JSON-string CONTAINS (the old
//     ANY(... IN <json string> ...) silently never matched).
//   - extract_role_trust_relationships emits CAN_ASSUME for explicit-principal trust
//     AND for account-root trust (arn:aws:iam::<ACCT>:root).
func TestPrivescEnrichersPopulate(t *testing.T) {
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

	// adminUser carries AdministratorAccess as a JSON STRING (the real flattened form).
	// explicitRole's trust doc names the attacker ARN; rootRole's trust doc names the
	// same-account root; foreignAttacker is in a different account (must NOT get root
	// trust to rootRole).
	_, err = db.Query(ctx, `
		CREATE (adminUser:User:Principal {Arn: 'arn:aws:iam::123456789012:user/admin',
			AttachedManagedPolicies: '[{"PolicyName":"AdministratorAccess","PolicyArn":"arn:aws:iam::aws:policy/AdministratorAccess"}]'})
		CREATE (plainUser:User:Principal {Arn: 'arn:aws:iam::123456789012:user/plain',
			AttachedManagedPolicies: '[{"PolicyName":"ReadOnlyAccess","PolicyArn":"arn:aws:iam::aws:policy/ReadOnlyAccess"}]'})
		CREATE (attacker:User:Principal {Arn: 'arn:aws:iam::123456789012:user/attacker'})
		CREATE (foreign:User:Principal  {Arn: 'arn:aws:iam::999999999999:user/foreign'})
		CREATE (explicitRole:Role:Principal {Arn: 'arn:aws:iam::123456789012:role/explicit',
			AssumeRolePolicyDocument: '{"Statement":[{"Principal":{"AWS":"arn:aws:iam::123456789012:user/attacker"}}]}'})
		CREATE (rootRole:Role:Principal {Arn: 'arn:aws:iam::123456789012:role/root-trusted',
			AssumeRolePolicyDocument: '{"Statement":[{"Principal":{"AWS":"arn:aws:iam::123456789012:root"}}]}'})
	`, nil)
	require.NoError(t, err, "seed enricher graph")

	require.NoError(t, EnrichAWS(ctx, db), "EnrichAWS")

	t.Run("is_admin_set_via_contains", func(t *testing.T) {
		result, err := db.Query(ctx,
			`MATCH (p {Arn: 'arn:aws:iam::123456789012:user/admin'}) RETURN coalesce(p._is_admin,false) AS adm`, nil)
		require.NoError(t, err)
		adm, _ := result.Records[0]["adm"].(bool)
		assert.True(t, adm, "_is_admin must be set on the AdministratorAccess user (JSON-string CONTAINS fix)")
	})

	t.Run("is_admin_not_set_on_non_admin", func(t *testing.T) {
		result, err := db.Query(ctx,
			`MATCH (p {Arn: 'arn:aws:iam::123456789012:user/plain'}) RETURN coalesce(p._is_admin,false) AS adm`, nil)
		require.NoError(t, err)
		adm, _ := result.Records[0]["adm"].(bool)
		assert.False(t, adm, "_is_admin must NOT be set on a ReadOnlyAccess user")
	})

	t.Run("can_assume_explicit_principal_trust", func(t *testing.T) {
		result, err := db.Query(ctx,
			`MATCH (a {Arn: 'arn:aws:iam::123456789012:user/attacker'})-[:CAN_ASSUME]->(r {Arn: 'arn:aws:iam::123456789012:role/explicit'})
			 RETURN count(*) AS n`, nil)
		require.NoError(t, err)
		n, _ := toInt64(result.Records[0]["n"])
		assert.GreaterOrEqual(t, int(n), 1, "explicit-principal trust must produce a CAN_ASSUME edge")
	})

	t.Run("can_assume_account_root_trust", func(t *testing.T) {
		result, err := db.Query(ctx,
			`MATCH (a {Arn: 'arn:aws:iam::123456789012:user/attacker'})-[:CAN_ASSUME]->(r {Arn: 'arn:aws:iam::123456789012:role/root-trusted'})
			 RETURN count(*) AS n`, nil)
		require.NoError(t, err)
		n, _ := toInt64(result.Records[0]["n"])
		assert.GreaterOrEqual(t, int(n), 1,
			"account-root trust must produce a CAN_ASSUME edge for a same-account principal")
	})

	t.Run("can_assume_root_trust_scoped_to_same_account", func(t *testing.T) {
		// A principal in a DIFFERENT account must not get a root-trust CAN_ASSUME edge
		// to a role whose trust doc only names the role's own account root.
		result, err := db.Query(ctx,
			`MATCH (f {Arn: 'arn:aws:iam::999999999999:user/foreign'})-[:CAN_ASSUME]->(r {Arn: 'arn:aws:iam::123456789012:role/root-trusted'})
			 RETURN count(*) AS n`, nil)
		require.NoError(t, err)
		n, _ := toInt64(result.Records[0]["n"])
		assert.Equal(t, int64(0), n,
			"cross-account principal must NOT get a root-trust CAN_ASSUME edge (root trust is account-scoped)")
	})
}

// TestPrivescNoCartesianFanOut is the structural FP assertion from the Phase-0 baseline:
// after EnrichAWS, no single non-admin principal whose ONLY escalation primitive is a
// (now-corrected) representative method may emit CAN_PRIVESC to a large fan of distinct
// targets. It seeds a population of bystander principals plus FP attackers that hold a
// permission but FAIL the structural guard, then asserts those FP attackers emit ZERO
// edges and that no source's distinct-target out-degree scales with the population.
func TestPrivescNoCartesianFanOut(t *testing.T) {
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

	// 20 bystander principals create a population the old cartesian fan-out would
	// have reached. FP attackers each hold a permission but miss the structural guard:
	//   fp_cpv: CreatePolicyVersion on a policy NOT attached to itself.
	//   fp_sts: STS_ASSUMEROLE with NO CAN_ASSUME trust edge.
	//   fp_ec2: PassRole (to a privileged role with an instance profile) + RunInstances,
	//           but the role trusts ONLY lambda.amazonaws.com, not ec2 — so the ec2-trust
	//           guard is the SOLE reason the edge is suppressed (not a label mismatch).
	//   fp_cfn: CreateChangeSet/ExecuteChangeSet on DIFFERENT stacks.
	//   fp_pr:  PassRole+RunInstances to a role that trusts ec2 and has an instance profile
	//           but is NOT privileged — the privileged-target guard is the SOLE rejection.
	//   fp_hr:  Lambda UpdateFunctionCode+Invoke on a function whose HAS_ROLE execution role
	//           is NOT privileged — the privileged-target guard is the SOLE rejection.
	_, err = db.Query(ctx, `
		UNWIND range(1, 20) AS i
		CREATE (:Principal {Arn: 'arn:aws:iam::123456789012:user/bystander-' + toString(i), _is_admin: false})
	`, nil)
	require.NoError(t, err, "seed bystander population")

	_, err = db.Query(ctx, `
		CREATE (cpv:Principal {Arn: 'arn:aws:iam::123456789012:user/fp_cpv', _is_admin: false})
		CREATE (cpvPolicy:Resource {Arn: 'arn:aws:iam::123456789012:policy/unattached'})
		CREATE (sts:Principal {Arn: 'arn:aws:iam::123456789012:user/fp_sts', _is_admin: false})
		CREATE (stsRole:Principal {Arn: 'arn:aws:iam::123456789012:role/no-trust', _is_admin: true})
		CREATE (stsRes:Resource {Arn: 'arn:aws:sts::123456789012:role/no-trust'})
		CREATE (ec2:Principal {Arn: 'arn:aws:iam::123456789012:user/fp_ec2', _is_admin: false})
		CREATE (ec2Role:Principal {Arn: 'arn:aws:iam::123456789012:role/lambda-only', _is_admin: true,
			trusted_services: ['lambda.amazonaws.com'],
			InstanceProfileList: '[{"Arn":"arn:aws:iam::123456789012:instance-profile/ip"}]'})
		CREATE (ec2Res:Resource {Arn: 'arn:aws:ec2:us-east-1:123456789012:instance/i-1'})
		CREATE (cfn:Principal {Arn: 'arn:aws:iam::123456789012:user/fp_cfn', _is_admin: false})
		CREATE (cfnStackA:Resource {Arn: 'arn:aws:cloudformation:us-east-1:123456789012:stack/a'})
		CREATE (cfnStackB:Resource {Arn: 'arn:aws:cloudformation:us-east-1:123456789012:stack/b'})
		CREATE (pr:Principal {Arn: 'arn:aws:iam::123456789012:user/fp_pr', _is_admin: false})
		CREATE (prRole:Role:Principal {Arn: 'arn:aws:iam::123456789012:role/unpriv-ec2', _is_admin: false,
			trusted_services: ['ec2.amazonaws.com'],
			InstanceProfileList: '[{"Arn":"arn:aws:iam::123456789012:instance-profile/ip"}]'})
		CREATE (prRes:Resource {Arn: 'arn:aws:ec2:us-east-1:123456789012:reservation/r-1'})
		CREATE (hr:Principal {Arn: 'arn:aws:iam::123456789012:user/fp_hr', _is_admin: false})
		CREATE (hrFn:Resource {Arn: 'arn:aws:lambda:us-east-1:123456789012:function:unpriv'})
		CREATE (hrRole:Role:Principal {Arn: 'arn:aws:iam::123456789012:role/unpriv-exec', _is_admin: false})
		WITH cpv, cpvPolicy, sts, stsRes, ec2, ec2Role, ec2Res, cfn, cfnStackA, cfnStackB,
			pr, prRole, prRes, hr, hrFn, hrRole
		MERGE (cpv)-[:IAM_CREATEPOLICYVERSION]->(cpvPolicy)
		MERGE (sts)-[:STS_ASSUMEROLE]->(stsRes)
		MERGE (ec2)-[:IAM_PASSROLE]->(ec2Role)
		MERGE (ec2)-[:EC2_RUNINSTANCES]->(ec2Res)
		MERGE (cfn)-[:CLOUDFORMATION_CREATECHANGESET]->(cfnStackA)
		MERGE (cfn)-[:CLOUDFORMATION_EXECUTECHANGESET]->(cfnStackB)
		MERGE (pr)-[:IAM_PASSROLE]->(prRole)
		MERGE (pr)-[:EC2_RUNINSTANCES]->(prRes)
		MERGE (hr)-[:LAMBDA_UPDATEFUNCTIONCODE]->(hrFn)
		MERGE (hr)-[:LAMBDA_INVOKEFUNCTION]->(hrFn)
		MERGE (hrFn)-[:HAS_ROLE]->(hrRole)
	`, nil)
	require.NoError(t, err, "seed FP attackers")

	require.NoError(t, EnrichAWS(ctx, db), "EnrichAWS")

	// FP attackers must emit ZERO CAN_PRIVESC edges (they fail the structural guard).
	for _, fp := range []string{"fp_cpv", "fp_sts", "fp_ec2", "fp_cfn", "fp_pr", "fp_hr"} {
		t.Run("fp_zero_edges_"+fp, func(t *testing.T) {
			result, err := db.Query(ctx, fmt.Sprintf(
				`MATCH (a {Arn: 'arn:aws:iam::123456789012:user/%s'})-[r:CAN_PRIVESC]->() RETURN count(r) AS n`, fp), nil)
			require.NoError(t, err)
			n, _ := toInt64(result.Records[0]["n"])
			assert.Equal(t, int64(0), n,
				"FP principal %s must emit ZERO CAN_PRIVESC edges (failed the structural guard)", fp)
		})
	}

	// Cartesian regression guard: no source may reach a large fan of DISTINCT targets.
	// With the cartesian bug a single source reached ~all 26 principals; corrected,
	// the max distinct-target out-degree across all non-admin sources must stay small.
	t.Run("no_source_reaches_many_distinct_targets", func(t *testing.T) {
		result, err := db.Query(ctx, `
			MATCH (a:Principal)-[:CAN_PRIVESC]->(b)
			WITH a, count(DISTINCT b) AS targets
			RETURN coalesce(max(targets), 0) AS maxTargets
		`, nil)
		require.NoError(t, err)
		maxTargets, _ := toInt64(result.Records[0]["maxTargets"])
		assert.LessOrEqual(t, maxTargets, int64(3),
			"no single source should reach >3 distinct CAN_PRIVESC targets — a large fan is the cartesian-bug signature")
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
