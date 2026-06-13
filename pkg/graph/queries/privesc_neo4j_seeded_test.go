//go:build integration

package queries

import (
	"context"
	"fmt"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/graph"
	"github.com/praetorian-inc/aurelian/pkg/graph/adapters"
	transformaws "github.com/praetorian-inc/aurelian/pkg/graph/transformers/aws"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/types"
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
				'amplify.amazonaws.com',
				'codebuild.amazonaws.com'
			],
			// Cognito identity-pool roles trust the service as a FEDERATED principal, surfaced
			// by the transformer as trusted_federated (NOT trusted_services). Seeding it here
			// (and only here) keeps cognito_set_identity_pool_roles non-vacuous: removing the
			// trusted_federated guard branch leaves cognito untrusted -> 0 edges -> test fails.
			trusted_federated: ['cognito-identity.amazonaws.com'],
			InstanceProfileList: '[{"Arn":"arn:aws:iam::123456789012:instance-profile/ip"}]'})
		// privUser carries the REAL collected signals the tightened principal-access methods now
		// guard on: AccessKeyCount < 2 (iam:CreateAccessKey can mint a key) and HasLoginProfile
		// (iam:UpdateLoginProfile can reset an existing console password). Seeding the real props
		// keeps iam_create_access_key / iam_update_login_profile firing on the true signal, not
		// only the fail-open fallback.
		CREATE (privUser:User:Principal {Arn: '%s', _is_admin: true, AccessKeyCount: 1, HasLoginProfile: true})
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
		CREATE (batchJobDef:Resource {_resourceType: 'AWS::Batch::JobDefinition',        Arn: 'arn:aws:batch:us-east-1:123456789012:job-definition/jd:1'})
		CREATE (codeInterp:Resource  {_resourceType: 'AWS::BedrockAgentCore::CodeInterpreter', Arn: 'arn:aws:bedrock-agentcore:us-east-1:123456789012:code-interpreter/ci-1'})
		WITH a, adminRole, privUser, privGroup, joinGroup, policy, svc, wildcard, stack,
			cfnStack, cfnStackSet, cbProject, glueEndpoint, glueJob, appRunner,
			ecsTaskDef, sfnMachine, smNotebook, ec2Instance, batchJobDef, codeInterp
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
		// Batch job definition / Bedrock code interpreter run as adminRole, reached by the
		// re-pointed batch_submit_job / bedrock_access_code_interpreter methods via HAS_ROLE.
		MERGE (batchJobDef)-[:HAS_ROLE]->(adminRole)
		MERGE (codeInterp)-[:HAS_ROLE]->(adminRole)
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

		// --- Multi-perm same stub / resource-service-role takeover ---
		// cloudformation_changeset targets the CFN stack's SERVICE ROLE via
		// (cfnStack)-[:HAS_ROLE]->(adminRole), not the bare stack stub: requires both
		// CreateChangeSet AND ExecuteChangeSet, then lands on the privileged role.
		{p + "cloudformation_changeset", targetAdminRole},
		// batch_submit_job / bedrock_access_code_interpreter target the backing resource's role
		// via (JobDefinition|CodeInterpreter)-[:HAS_ROLE]->(adminRole), not the service-wildcard
		// stub: requires the resource node + a trusting privileged role.
		{p + "batch_submit_job", targetAdminRole},
		{p + "bedrock_access_code_interpreter", targetAdminRole},
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
// the passed/assumed/HAS_ROLE methods all converge onto the SAME privileged role target.
// CAN_PRIVESC is multi-edge (one edge per method), so each converging method contributes its
// own method-edge to that role (>= 1 edge to the role), and no method fans out to an
// unrelated principal (no edge to any bystander node).
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
		t.Logf("  path: %s → %s (%d hops) methods=%v", attacker, rec["target_arn"], hops, rec["methods"])
	}

	t.Run("methods_column_present_and_sized_to_hops", func(t *testing.T) {
		// The analysis query must surface the per-hop method sequence so consumers can
		// enumerate distinct method-paths. Each record's `methods` list must have exactly
		// hop_count entries (one method per CAN_PRIVESC edge traversed).
		require.NotEmpty(t, result.Records, "analysis query returned no paths")
		for _, rec := range result.Records {
			methods, ok := rec["methods"].([]any)
			require.True(t, ok, "methods column must be a list, got %T", rec["methods"])
			hops, _ := toInt64(rec["hop_count"])
			assert.Len(t, methods, int(hops),
				"methods list length must equal hop_count (%d) for %v → %v", hops, rec["attacker_arn"], rec["target_arn"])
		}
	})

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
// Seeds a PassRole+AppRunner scenario where the passed
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
			t.Logf("Found: %s → %s (%v hops) methods=%v", rec["attacker_arn"], rec["target_arn"], rec["hop_count"], rec["methods"])
		}
	}
	assert.True(t, found,
		"PassRole+AppRunner attacker must appear in analysis output — "+
			"if this fails, apprunner_create_service has regressed: the scoped CAN_PRIVESC edge must point to the passed :Principal role, not a :Resource")
}

// TestPrivescMultiEdgePerMethod is the focused proof of the multi-edge model: a single
// (attacker, target) pair reachable by TWO distinct privesc methods must yield TWO distinct
// CAN_PRIVESC edges (one per method), and the analysis query must surface them as TWO
// distinct method-paths. Under the old single-edge model these would have collapsed onto
// one edge with a last-write-wins `method`, hiding the second path.
//
// Seed: attacker can both assume the admin role (sts:AssumeRole, via CAN_ASSUME +
// STS_ASSUMEROLE) AND write an inline policy onto it then assume it (iam:PutRolePolicy, via
// CAN_ASSUME + IAM_PUTROLEPOLICY on the SAME role). Both target the same admin role.
func TestPrivescMultiEdgePerMethod(t *testing.T) {
	ctx := context.Background()

	boltURL, cleanup, err := startNeo4jContainer(ctx)
	require.NoError(t, err, "start Neo4j container")
	t.Cleanup(cleanup)

	cfg := graph.NewConfig(boltURL, "", "")
	db, err := adapters.NewNeo4jAdapter(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	const adminARN = "arn:aws:iam::123456789012:role/multi-method-admin"

	_, err = db.Query(ctx, fmt.Sprintf(`
		CREATE (attacker:Principal {Arn: '%s', _is_admin: false})
		CREATE (admin:Role:Principal {Arn: '%s', _is_admin: true})
		CREATE (svc:Resource {Arn: '%s'})
		WITH attacker, admin, svc
		// CAN_ASSUME trust path to admin (required by both methods).
		MERGE (attacker)-[:CAN_ASSUME]->(admin)
		// sts:AssumeRole: independent STS_ASSUMEROLE permission.
		MERGE (attacker)-[:STS_ASSUMEROLE]->(svc)
		// iam:PutRolePolicy: write inline policy onto the SAME assumable role.
		MERGE (attacker)-[:IAM_PUTROLEPOLICY]->(admin)
	`, attackerARN, adminARN, svcResourceARN), nil)
	require.NoError(t, err, "seed multi-method graph")

	require.NoError(t, EnrichAWS(ctx, db), "EnrichAWS should succeed")

	t.Run("two_distinct_method_edges_between_pair", func(t *testing.T) {
		result, err := db.Query(ctx, fmt.Sprintf(`
			MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(v {Arn: '%s'})
			RETURN count(DISTINCT r.method) AS methods, count(r) AS edges`,
			attackerARN, adminARN), nil)
		require.NoError(t, err)
		require.Len(t, result.Records, 1)
		methods, _ := toInt64(result.Records[0]["methods"])
		edges, _ := toInt64(result.Records[0]["edges"])
		t.Logf("attacker→admin: %d edges, %d distinct methods", edges, methods)
		assert.GreaterOrEqual(t, int(methods), 2,
			"a pair reachable by ≥2 methods must carry ≥2 distinct CAN_PRIVESC method-edges (multi-edge model)")
		assert.GreaterOrEqual(t, int(edges), 2,
			"distinct methods must each be their own edge, not collapsed onto one")
	})

	t.Run("both_specific_method_edges_exist", func(t *testing.T) {
		for _, m := range []string{"sts:AssumeRole", "iam:PutRolePolicy"} {
			result, err := db.Query(ctx, fmt.Sprintf(`
				MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC {method: '%s'}]->(v {Arn: '%s'})
				RETURN count(r) AS n`, attackerARN, m, adminARN), nil)
			require.NoError(t, err)
			n, _ := toInt64(result.Records[0]["n"])
			assert.Equal(t, int64(1), n, "exactly one CAN_PRIVESC edge for method %q", m)
		}
	})

	t.Run("analysis_query_returns_two_distinct_method_paths", func(t *testing.T) {
		result, err := RunPlatformQuery(ctx, db, "aws/analysis/privesc_paths", nil)
		require.NoError(t, err)
		require.NotNil(t, result)

		distinctMethods := map[string]bool{}
		for _, rec := range result.Records {
			if rec["attacker_arn"] != attackerARN || rec["target_arn"] != adminARN {
				continue
			}
			methods, ok := rec["methods"].([]any)
			require.True(t, ok, "methods column must be a list, got %T", rec["methods"])
			require.Len(t, methods, 1, "this is a 1-hop path, so exactly one method per record")
			m, _ := methods[0].(string)
			distinctMethods[m] = true
			t.Logf("  method-path: %s → %s methods=%v", rec["attacker_arn"], rec["target_arn"], methods)
		}
		assert.GreaterOrEqual(t, len(distinctMethods), 2,
			"analysis query must enumerate ≥2 distinct method-paths for the multi-method pair, got %v", distinctMethods)
	})
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

			// CAN_PRIVESC is multi-edge (one edge per method). Match the edge BY method so
			// the assertion stays sound even when a pair is reachable by several methods —
			// we verify THIS method's edge exists to the passed role (roleARN) and carries
			// the expected severity. We do NOT assert "exactly one edge total" between the pair.
			result, err := db.Query(ctx,
				fmt.Sprintf(`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC {method: '%s'}]->(v {Arn: '%s'})
				             RETURN r.method AS method, r.severity AS severity`,
					attackerARN, tc.wantMethod, roleARN),
				nil)
			require.NoError(t, err)
			require.Len(t, result.Records, 1,
				"expected exactly 1 CAN_PRIVESC edge for method %q from attacker to passed role", tc.wantMethod)

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
	//   fp_cfn: CreateChangeSet/ExecuteChangeSet on stacks that carry NO (Stack)-[:HAS_ROLE]->
	//           (privileged role) edge — the changeset method requires a
	//           privileged stack service role reached via HAS_ROLE, so the missing link is the
	//           SOLE rejection (fail-closed: a roleless stack confers nothing).
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
		CREATE (cfnStackA:Resource {Arn: 'arn:aws:cloudformation:us-east-1:123456789012:stack/a', _resourceType: 'AWS::CloudFormation::Stack'})
		CREATE (cfnStackB:Resource {Arn: 'arn:aws:cloudformation:us-east-1:123456789012:stack/b', _resourceType: 'AWS::CloudFormation::Stack'})
		CREATE (cfnUnprivRole:Role:Principal {Arn: 'arn:aws:iam::123456789012:role/unpriv-cfn', _is_admin: false})
		CREATE (pr:Principal {Arn: 'arn:aws:iam::123456789012:user/fp_pr', _is_admin: false})
		CREATE (prRole:Role:Principal {Arn: 'arn:aws:iam::123456789012:role/unpriv-ec2', _is_admin: false,
			trusted_services: ['ec2.amazonaws.com'],
			InstanceProfileList: '[{"Arn":"arn:aws:iam::123456789012:instance-profile/ip"}]'})
		CREATE (prRes:Resource {Arn: 'arn:aws:ec2:us-east-1:123456789012:reservation/r-1'})
		CREATE (hr:Principal {Arn: 'arn:aws:iam::123456789012:user/fp_hr', _is_admin: false})
		CREATE (hrFn:Resource {Arn: 'arn:aws:lambda:us-east-1:123456789012:function:unpriv'})
		CREATE (hrRole:Role:Principal {Arn: 'arn:aws:iam::123456789012:role/unpriv-exec', _is_admin: false})
		WITH cpv, cpvPolicy, sts, stsRes, ec2, ec2Role, ec2Res, cfn, cfnStackA, cfnStackB,
			cfnUnprivRole, pr, prRole, prRes, hr, hrFn, hrRole
		MERGE (cpv)-[:IAM_CREATEPOLICYVERSION]->(cpvPolicy)
		MERGE (sts)-[:STS_ASSUMEROLE]->(stsRes)
		MERGE (ec2)-[:IAM_PASSROLE]->(ec2Role)
		MERGE (ec2)-[:EC2_RUNINSTANCES]->(ec2Res)
		MERGE (cfn)-[:CLOUDFORMATION_CREATECHANGESET]->(cfnStackA)
		MERGE (cfn)-[:CLOUDFORMATION_EXECUTECHANGESET]->(cfnStackB)
		// Stacks carry HAS_ROLE to a NON-privileged role, so the privileged-target guard is
		// the SOLE reason fp_cfn is suppressed (not a missing HAS_ROLE link or _resourceType).
		MERGE (cfnStackA)-[:HAS_ROLE]->(cfnUnprivRole)
		MERGE (cfnStackB)-[:HAS_ROLE]->(cfnUnprivRole)
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

// TestResourceToRoleNameFormHasRole locks down the NAME-form branch of the resource_to_role
// enricher (Finding 1 regression). An AWS::EC2::Instance's IamInstanceProfile can be the
// instance-profile ARN OR just the profile NAME (CloudControl-collected instances commonly
// carry the NAME). Here the instance carries the NAME ('EC2-Profile') and the role's
// InstanceProfileList is ARN-ONLY (no InstanceProfileName key) — the worst case. The fix's
// second clause ('instance-profile/' + name + '"') must still create the HAS_ROLE edge.
//
// This FAILS against the old single-clause query ('"' + name + '"'), since '"EC2-Profile"'
// does not appear in '...:instance-profile/EC2-Profile"' (the preceding char is '/'),
// proving the test is non-vacuous.
func TestResourceToRoleNameFormHasRole(t *testing.T) {
	ctx := context.Background()

	boltURL, cleanup, err := startNeo4jContainer(ctx)
	require.NoError(t, err, "start Neo4j container")
	t.Cleanup(cleanup)

	cfg := graph.NewConfig(boltURL, "", "")
	db, err := adapters.NewNeo4jAdapter(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	_, err = db.Query(ctx, "MATCH (n) DETACH DELETE n", nil)
	require.NoError(t, err, "clear db")

	const (
		instanceARN = "arn:aws:ec2:us-east-1:123456789012:instance/i-0name"
		nameRoleARN = "arn:aws:iam::123456789012:role/name-form-role"
		profileName = "EC2-Profile"
		profileList = `[{"Arn":"arn:aws:iam::123456789012:instance-profile/EC2-Profile"}]`
	)

	// Instance carries the NAME form; role's InstanceProfileList is ARN-only (no name key).
	_, err = db.Query(ctx, fmt.Sprintf(`
		CREATE (i:Resource {Arn: '%s', _resourceType: 'AWS::EC2::Instance', IamInstanceProfile: '%s'})
		CREATE (r:Role:Principal {Arn: '%s', InstanceProfileList: '%s'})
	`, instanceARN, profileName, nameRoleARN, profileList), nil)
	require.NoError(t, err, "seed name-form instance + ARN-only role")

	_, err = RunPlatformQuery(ctx, db, "aws/enrich/resource_to_role", nil)
	require.NoError(t, err, "run resource_to_role enricher")

	result, err := db.Query(ctx, fmt.Sprintf(
		`MATCH (i {Arn: '%s'})-[:HAS_ROLE]->(r {Arn: '%s'}) RETURN count(*) AS n`,
		instanceARN, nameRoleARN), nil)
	require.NoError(t, err)
	n, _ := toInt64(result.Records[0]["n"])
	assert.Equal(t, int64(1), n,
		"name-form IamInstanceProfile must link to the role via HAS_ROLE — the second anchored CONTAINS clause covers this; the old single-clause query misses it")
}

// TestResourceToRoleViaTransformerHasRole proves the instance HAS_ROLE link through
// the REAL production path, not hand-seeded top-level properties. The instance
// node is built by NodeFromAWSResource (which buries Properties as a JSON string
// and must PROMOTE IamInstanceProfile to a top-level node property) and written
// via the production CreateNodes path. The enricher then matches that promoted
// property against the role's InstanceProfileList. Without the promotion fix,
// resource.IamInstanceProfile is null on the written node and no HAS_ROLE edge is
// created — so this test is non-vacuous for the fix and demonstrates that
// ec2_ssm_association can now resolve (instance)-[:HAS_ROLE]->(victim) on real data.
func TestResourceToRoleViaTransformerHasRole(t *testing.T) {
	ctx := context.Background()

	boltURL, cleanup, err := startNeo4jContainer(ctx)
	require.NoError(t, err, "start Neo4j container")
	t.Cleanup(cleanup)

	cfg := graph.NewConfig(boltURL, "", "")
	db, err := adapters.NewNeo4jAdapter(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	_, err = db.Query(ctx, "MATCH (n) DETACH DELETE n", nil)
	require.NoError(t, err, "clear db")

	const (
		instanceARN = "arn:aws:ec2:us-east-1:123456789012:instance/i-0real"
		roleARN     = "arn:aws:iam::123456789012:role/transformer-role"
		profileARN  = "arn:aws:iam::123456789012:instance-profile/ip"
		profileList = `[{"Arn":"arn:aws:iam::123456789012:instance-profile/ip"}]`
	)

	// Build the instance node via the production transformer (Properties carries
	// the instance-profile ARN; NodeFromAWSResource must promote it to top-level)
	// and write it via the production CreateNodes path — NOT a hand-seeded property.
	instanceNode := transformaws.NodeFromAWSResource(output.AWSResource{
		ResourceType: "AWS::EC2::Instance",
		ARN:          instanceARN,
		AccountRef:   "123456789012",
		Region:       "us-east-1",
		Properties:   map[string]any{"IamInstanceProfile": profileARN},
	})
	_, err = db.CreateNodes(ctx, []*graph.Node{instanceNode})
	require.NoError(t, err, "write transformer-built instance node")

	// Role with the JSON-string InstanceProfileList the enricher CONTAINS-matches.
	_, err = db.Query(ctx, fmt.Sprintf(
		`CREATE (r:Role:Principal {Arn: '%s', InstanceProfileList: '%s'})`,
		roleARN, profileList), nil)
	require.NoError(t, err, "seed role with InstanceProfileList")

	_, err = RunPlatformQuery(ctx, db, "aws/enrich/resource_to_role", nil)
	require.NoError(t, err, "run resource_to_role enricher")

	result, err := db.Query(ctx, fmt.Sprintf(
		`MATCH (i {arn: '%s'})-[:HAS_ROLE]->(r:Role {Arn: '%s'}) RETURN count(*) AS n`,
		instanceARN, roleARN), nil)
	require.NoError(t, err)
	n, _ := toInt64(result.Records[0]["n"])
	assert.Equal(t, int64(1), n,
		"transformer-built instance must link to the role via HAS_ROLE — requires NodeFromAWSResource to promote IamInstanceProfile to a top-level node property")
}

// TestPrivescChangesetStackRoleHasRole locks down cloudformation_changeset's link
// at the CFN stack's SERVICE ROLE via (Stack)-[:HAS_ROLE]->(role) — replacing the old
// fan-out to the bare stack stub. The attacker holds both change-set actions; the edge must
// land on the privileged stack role, and the privileged-target + HAS_ROLE + same-account +
// both-actions guards must each be the SOLE rejection in their respective FP cases.
//
// Non-vacuous: the happy case requires the HAS_ROLE edge AND a privileged role (removing
// either flips it to 0); each FP case isolates one guard. This is the synthetic proof that
// the re-pointed method fires to the real role, not a vacuous never-firing enricher.
func TestPrivescChangesetStackRoleHasRole(t *testing.T) {
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

	const (
		attacker = "arn:aws:iam::123456789012:user/cs-attacker"
		role     = "arn:aws:iam::123456789012:role/cs-stack-role"
		queryID  = "aws/enrich/privesc/cloudformation_changeset"
	)

	// setup seeds: attacker with both change-set actions on a stub, a CFN stack with the
	// given _is_admin role props, and (when hasRole) a (stack)-[:HAS_ROLE]->(role) edge.
	// actions controls which change-set permissions the attacker holds; roleAccount lets a
	// case place the role in another account to exercise the same-account guard.
	setup := func(actions, roleProps, roleAccount, hasRole string) string {
		roleARN := fmt.Sprintf("arn:aws:iam::%s:role/cs-stack-role", roleAccount)
		return fmt.Sprintf(`
			CREATE (a:User:Principal {Arn: '%s', _is_admin: false})
			CREATE (stub:Resource {Arn: 'arn:aws:cloudformation:us-east-1:123456789012:stack/stub'})
			CREATE (stack:Resource {Arn: 'arn:aws:cloudformation:us-east-1:123456789012:stack/s', _resourceType: 'AWS::CloudFormation::Stack'})
			CREATE (role:Role:Principal {Arn: '%s'%s})
			WITH a, stub, stack, role
			%s
			%s
		`, attacker, roleARN, roleProps, actions, hasRole)
	}
	const (
		bothActions = `MERGE (a)-[:CLOUDFORMATION_CREATECHANGESET]->(stub)
			MERGE (a)-[:CLOUDFORMATION_EXECUTECHANGESET]->(stub)`
		createOnly  = `MERGE (a)-[:CLOUDFORMATION_CREATECHANGESET]->(stub)`
		hasRoleEdge = `MERGE (stack)-[:HAS_ROLE]->(role)`
		noRoleEdge  = ``
	)

	// edgeCount counts CAN_PRIVESC edges from the attacker to the role (any account).
	edgeCount := func(t *testing.T, db graph.GraphDatabase) int64 {
		t.Helper()
		result, err := db.Query(ctx, fmt.Sprintf(
			`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(:Role) RETURN count(r) AS n`, attacker), nil)
		require.NoError(t, err)
		n, _ := toInt64(result.Records[0]["n"])
		return n
	}

	cases := []struct {
		name        string
		actions     string
		roleProps   string
		roleAccount string
		hasRole     string
		wantEdge    bool
		desc        string
	}{
		{
			name:        "admin_role_via_hasrole",
			actions:     bothActions,
			roleProps:   ", _is_admin: true",
			roleAccount: "123456789012",
			hasRole:     hasRoleEdge,
			wantEdge:    true,
			desc:        "both change-set actions + (stack)-[:HAS_ROLE]->(admin role) → edge fires to the role",
		},
		{
			name:        "no_hasrole_no_edge",
			actions:     bothActions,
			roleProps:   ", _is_admin: true",
			roleAccount: "123456789012",
			hasRole:     noRoleEdge,
			wantEdge:    false,
			desc:        "no HAS_ROLE link → roleless stack confers nothing → NO edge (HAS_ROLE is the sole rejection)",
		},
		{
			name:        "unprivileged_role_no_edge",
			actions:     bothActions,
			roleProps:   ", _is_admin: false",
			roleAccount: "123456789012",
			hasRole:     hasRoleEdge,
			wantEdge:    false,
			desc:        "stack role is NOT privileged → privileged-target guard is the sole rejection → NO edge",
		},
		{
			name:        "single_action_no_edge",
			actions:     createOnly,
			roleProps:   ", _is_admin: true",
			roleAccount: "123456789012",
			hasRole:     hasRoleEdge,
			wantEdge:    false,
			desc:        "only CreateChangeSet (no ExecuteChangeSet) → both-actions requirement is the sole rejection → NO edge",
		},
		{
			name:        "cross_account_role_no_edge",
			actions:     bothActions,
			roleProps:   ", _is_admin: true",
			roleAccount: "999999999999",
			hasRole:     hasRoleEdge,
			wantEdge:    false,
			desc:        "privileged stack role in a DIFFERENT account → same-account guard (ARN seg 4) is the sole rejection → NO edge",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := newAdapter(t)
			_, err := db.Query(ctx, "MATCH (n) DETACH DELETE n", nil)
			require.NoError(t, err, "clear db")
			_, err = db.Query(ctx, setup(tc.actions, tc.roleProps, tc.roleAccount, tc.hasRole), nil)
			require.NoError(t, err, "seed changeset graph")

			_, err = RunPlatformQuery(ctx, db, queryID, nil)
			require.NoError(t, err, "run cloudformation_changeset enricher")

			n := edgeCount(t, db)
			if tc.wantEdge {
				assert.Equal(t, int64(1), n, tc.desc)
			} else {
				assert.Equal(t, int64(0), n, tc.desc)
			}
		})
	}
}

// TestPrivescBatchJobRoleHasRole locks down batch_submit_job's link to the
// job definition's JOB ROLE via (JobDefinition)-[:HAS_ROLE]->(jobrole) — replacing the old
// existence-precondition stub. The attacker holds batch:SubmitJob; the edge must land on the
// privileged, ecs-tasks-trusting job role, and HAS_ROLE + trust + privileged-target +
// same-account must each be the SOLE rejection in their respective FP cases.
func TestPrivescBatchJobRoleHasRole(t *testing.T) {
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

	const (
		attacker = "arn:aws:iam::123456789012:user/batch-attacker"
		queryID  = "aws/enrich/privesc/batch_submit_job"
	)

	// setup seeds: attacker with batch:SubmitJob on a service stub, a Batch job definition,
	// and (when hasRole) a (jobdef)-[:HAS_ROLE]->(jobrole) edge. roleProps controls
	// _is_admin/trust; roleAccount exercises the same-account guard.
	setup := func(roleProps, roleAccount, hasRole string) string {
		roleARN := fmt.Sprintf("arn:aws:iam::%s:role/batch-job-role", roleAccount)
		return fmt.Sprintf(`
			CREATE (a:User:Principal {Arn: '%s', _is_admin: false})
			CREATE (svc:Resource {Arn: 'arn:aws:batch:us-east-1:123456789012:*'})
			CREATE (jobdef:Resource {Arn: 'arn:aws:batch:us-east-1:123456789012:job-definition/jd:1', _resourceType: 'AWS::Batch::JobDefinition'})
			CREATE (role:Role:Principal {Arn: '%s'%s})
			WITH a, svc, jobdef, role
			MERGE (a)-[:BATCH_SUBMITJOB]->(svc)
			%s
		`, attacker, roleARN, roleProps, hasRole)
	}
	const (
		hasRoleEdge = `MERGE (jobdef)-[:HAS_ROLE]->(role)`
		noRoleEdge  = ``
	)
	const (
		adminTrusted    = `, _is_admin: true, trusted_services: ['ecs-tasks.amazonaws.com']`
		unprivTrusted   = `, _is_admin: false, trusted_services: ['ecs-tasks.amazonaws.com']`
		adminWrongTrust = `, _is_admin: true, trusted_services: ['lambda.amazonaws.com']`
	)

	edgeCount := func(t *testing.T, db graph.GraphDatabase) int64 {
		t.Helper()
		result, err := db.Query(ctx, fmt.Sprintf(
			`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(:Role) RETURN count(r) AS n`, attacker), nil)
		require.NoError(t, err)
		n, _ := toInt64(result.Records[0]["n"])
		return n
	}

	cases := []struct {
		name        string
		roleProps   string
		roleAccount string
		hasRole     string
		wantEdge    bool
		desc        string
	}{
		{
			name:        "admin_role_via_hasrole",
			roleProps:   adminTrusted,
			roleAccount: "123456789012",
			hasRole:     hasRoleEdge,
			wantEdge:    true,
			desc:        "SubmitJob + (jobdef)-[:HAS_ROLE]->(ecs-tasks-trusting admin role) → edge fires to the role",
		},
		{
			name:        "no_hasrole_no_edge",
			roleProps:   adminTrusted,
			roleAccount: "123456789012",
			hasRole:     noRoleEdge,
			wantEdge:    false,
			desc:        "no HAS_ROLE link → roleless job definition confers nothing → NO edge (HAS_ROLE is the sole rejection)",
		},
		{
			name:        "unprivileged_role_no_edge",
			roleProps:   unprivTrusted,
			roleAccount: "123456789012",
			hasRole:     hasRoleEdge,
			wantEdge:    false,
			desc:        "job role is NOT privileged → privileged-target guard is the sole rejection → NO edge",
		},
		{
			name:        "wrong_trust_no_edge",
			roleProps:   adminWrongTrust,
			roleAccount: "123456789012",
			hasRole:     hasRoleEdge,
			wantEdge:    false,
			desc:        "job role does NOT trust ecs-tasks → trust guard is the sole rejection → NO edge",
		},
		{
			name:        "cross_account_role_no_edge",
			roleProps:   adminTrusted,
			roleAccount: "999999999999",
			hasRole:     hasRoleEdge,
			wantEdge:    false,
			desc:        "privileged job role in a DIFFERENT account → same-account guard (ARN seg 4) is the sole rejection → NO edge",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := newAdapter(t)
			_, err := db.Query(ctx, "MATCH (n) DETACH DELETE n", nil)
			require.NoError(t, err, "clear db")
			_, err = db.Query(ctx, setup(tc.roleProps, tc.roleAccount, tc.hasRole), nil)
			require.NoError(t, err, "seed batch graph")

			_, err = RunPlatformQuery(ctx, db, queryID, nil)
			require.NoError(t, err, "run batch_submit_job enricher")

			n := edgeCount(t, db)
			if tc.wantEdge {
				assert.Equal(t, int64(1), n, tc.desc)
			} else {
				assert.Equal(t, int64(0), n, tc.desc)
			}
		})
	}
}

// TestPrivescCodeInterpreterRoleHasRole locks down bedrock_access_code_interpreter's
// link to the interpreter's EXECUTION ROLE via
// (CodeInterpreter)-[:HAS_ROLE]->(execrole) — replacing the old existence-precondition stub.
// The attacker holds bedrock-agentcore:InvokeSession; the edge must land on the privileged,
// bedrock-agentcore-trusting execution role, and HAS_ROLE + trust + privileged-target +
// same-account must each be the SOLE rejection in their respective FP cases.
func TestPrivescCodeInterpreterRoleHasRole(t *testing.T) {
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

	const (
		attacker = "arn:aws:iam::123456789012:user/bedrock-attacker"
		queryID  = "aws/enrich/privesc/bedrock_access_code_interpreter"
	)

	setup := func(roleProps, roleAccount, hasRole string) string {
		roleARN := fmt.Sprintf("arn:aws:iam::%s:role/ci-exec-role", roleAccount)
		return fmt.Sprintf(`
			CREATE (a:User:Principal {Arn: '%s', _is_admin: false})
			CREATE (svc:Resource {Arn: 'arn:aws:bedrock-agentcore:us-east-1:123456789012:*'})
			CREATE (ci:Resource {Arn: 'arn:aws:bedrock-agentcore:us-east-1:123456789012:code-interpreter/ci-1', _resourceType: 'AWS::BedrockAgentCore::CodeInterpreter'})
			CREATE (role:Role:Principal {Arn: '%s'%s})
			WITH a, svc, ci, role
			MERGE (a)-[:`+"`BEDROCK-AGENTCORE_INVOKESESSION`"+`]->(svc)
			%s
		`, attacker, roleARN, roleProps, hasRole)
	}
	const (
		hasRoleEdge = `MERGE (ci)-[:HAS_ROLE]->(role)`
		noRoleEdge  = ``
	)
	const (
		adminTrusted    = `, _is_admin: true, trusted_services: ['bedrock-agentcore.amazonaws.com']`
		unprivTrusted   = `, _is_admin: false, trusted_services: ['bedrock-agentcore.amazonaws.com']`
		adminWrongTrust = `, _is_admin: true, trusted_services: ['lambda.amazonaws.com']`
	)

	edgeCount := func(t *testing.T, db graph.GraphDatabase) int64 {
		t.Helper()
		result, err := db.Query(ctx, fmt.Sprintf(
			`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(:Role) RETURN count(r) AS n`, attacker), nil)
		require.NoError(t, err)
		n, _ := toInt64(result.Records[0]["n"])
		return n
	}

	cases := []struct {
		name        string
		roleProps   string
		roleAccount string
		hasRole     string
		wantEdge    bool
		desc        string
	}{
		{
			name:        "admin_role_via_hasrole",
			roleProps:   adminTrusted,
			roleAccount: "123456789012",
			hasRole:     hasRoleEdge,
			wantEdge:    true,
			desc:        "InvokeSession + (ci)-[:HAS_ROLE]->(bedrock-agentcore-trusting admin role) → edge fires to the role",
		},
		{
			name:        "no_hasrole_no_edge",
			roleProps:   adminTrusted,
			roleAccount: "123456789012",
			hasRole:     noRoleEdge,
			wantEdge:    false,
			desc:        "no HAS_ROLE link → roleless interpreter confers nothing → NO edge (HAS_ROLE is the sole rejection)",
		},
		{
			name:        "unprivileged_role_no_edge",
			roleProps:   unprivTrusted,
			roleAccount: "123456789012",
			hasRole:     hasRoleEdge,
			wantEdge:    false,
			desc:        "execution role is NOT privileged → privileged-target guard is the sole rejection → NO edge",
		},
		{
			name:        "wrong_trust_no_edge",
			roleProps:   adminWrongTrust,
			roleAccount: "123456789012",
			hasRole:     hasRoleEdge,
			wantEdge:    false,
			desc:        "execution role does NOT trust bedrock-agentcore → trust guard is the sole rejection → NO edge",
		},
		{
			name:        "cross_account_role_no_edge",
			roleProps:   adminTrusted,
			roleAccount: "999999999999",
			hasRole:     hasRoleEdge,
			wantEdge:    false,
			desc:        "privileged execution role in a DIFFERENT account → same-account guard (ARN seg 4) is the sole rejection → NO edge",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := newAdapter(t)
			_, err := db.Query(ctx, "MATCH (n) DETACH DELETE n", nil)
			require.NoError(t, err, "clear db")
			_, err = db.Query(ctx, setup(tc.roleProps, tc.roleAccount, tc.hasRole), nil)
			require.NoError(t, err, "seed bedrock graph")

			_, err = RunPlatformQuery(ctx, db, queryID, nil)
			require.NoError(t, err, "run bedrock_access_code_interpreter enricher")

			n := edgeCount(t, db)
			if tc.wantEdge {
				assert.Equal(t, int64(1), n, tc.desc)
			} else {
				assert.Equal(t, int64(0), n, tc.desc)
			}
		})
	}
}

// TestPrivescAccessKeyCountGuard locks down the real <2-active-keys precondition for
// iam_create_access_key. The method now guards on the collected target.AccessKeyCount:
//   - count >= 2  → NO edge (CreateAccessKey would hit the 2-key limit).
//   - count <  2  → edge fires on the real signal alone (no DeleteAccessKey proxy needed).
//   - count ABSENT (pre-enricher graph) → FAIL-OPEN to the original DeleteAccessKey proxy.
//
// Non-vacuous: dropping the AccessKeyCount branch (leaving only the proxy) would make the
// "count=1, no proxy" case fire — but it must NOT, since the real signal is the gate. And
// dropping the IS NULL fail-open would make the "absent, with proxy" case stop firing.
func TestPrivescAccessKeyCountGuard(t *testing.T) {
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

	const (
		attacker = "arn:aws:iam::123456789012:user/ak-attacker"
		victim   = "arn:aws:iam::123456789012:user/ak-victim"
	)
	const queryID = "aws/enrich/privesc/iam_create_access_key"

	// setup builds the attacker→victim graph. victimProps lets each case set/omit the
	// AccessKeyCount prop; withProxy adds the IAM_DELETEACCESSKEY fallback edge.
	setup := func(victimProps, withProxy string) string {
		return fmt.Sprintf(`
			CREATE (a:User:Principal {Arn: '%s', _is_admin: false})
			CREATE (v:User:Principal {Arn: '%s', _is_admin: true%s})
			WITH a, v
			MERGE (a)-[:IAM_CREATEACCESSKEY]->(v)
			%s
		`, attacker, victim, victimProps, withProxy)
	}
	const proxyEdge = "MERGE (a)-[:IAM_DELETEACCESSKEY]->(v)"

	edgeCount := func(t *testing.T, db graph.GraphDatabase) int64 {
		t.Helper()
		result, err := db.Query(ctx, fmt.Sprintf(
			`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(v {Arn: '%s'}) RETURN count(r) AS n`,
			attacker, victim), nil)
		require.NoError(t, err)
		n, _ := toInt64(result.Records[0]["n"])
		return n
	}

	cases := []struct {
		name        string
		victimProps string
		withProxy   string
		wantEdge    bool
		desc        string
	}{
		{
			name:        "count_2_no_edge",
			victimProps: ", AccessKeyCount: 2",
			withProxy:   proxyEdge,
			wantEdge:    false,
			desc:        "victim already holds 2 active keys → CreateAccessKey limit hit → NO edge even with the DeleteAccessKey proxy present",
		},
		{
			name:        "count_1_edge_on_real_signal",
			victimProps: ", AccessKeyCount: 1",
			withProxy:   "",
			wantEdge:    true,
			desc:        "victim has <2 active keys → edge fires on the REAL signal alone, no DeleteAccessKey proxy required",
		},
		{
			name:        "count_absent_failopen_with_proxy",
			victimProps: "",
			withProxy:   proxyEdge,
			wantEdge:    true,
			desc:        "AccessKeyCount absent (pre-enricher graph) → FAIL-OPEN to the DeleteAccessKey proxy → edge fires as before",
		},
		{
			name:        "count_absent_no_proxy_no_edge",
			victimProps: "",
			withProxy:   "",
			wantEdge:    false,
			desc:        "AccessKeyCount absent AND no DeleteAccessKey proxy → original proxy precondition unmet → NO edge (proves fail-open is the proxy, not unconditional)",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := newAdapter(t)
			_, err := db.Query(ctx, "MATCH (n) DETACH DELETE n", nil)
			require.NoError(t, err)
			_, err = db.Query(ctx, setup(tc.victimProps, tc.withProxy), nil)
			require.NoError(t, err, "seed")

			_, err = RunPlatformQuery(ctx, db, queryID, nil)
			require.NoError(t, err, "run %s", queryID)

			n := edgeCount(t, db)
			if tc.wantEdge {
				assert.GreaterOrEqual(t, n, int64(1), tc.desc)
			} else {
				assert.Equal(t, int64(0), n, tc.desc)
			}
		})
	}
}

// TestPrivescLoginProfileGuard locks down the real existing-login-profile precondition for
// iam_update_login_profile. The method guards on the collected target.HasLoginProfile, and the
// victim node is built via the REAL NodeFromGaadUser serialization path (not a hand-seeded
// Cypher prop) so the test proves the production collector can actually suppress:
//   - HasLoginProfile = false (non-nil) → NO edge (UpdateLoginProfile returns NoSuchEntity).
//   - HasLoginProfile = true            → edge fires.
//   - HasLoginProfile nil (unknown)     → field serializes to null → dropped → ABSENT →
//     FAIL-OPEN (coalesce default true) → edge fires as before.
//
// Non-vacuous: dropping the HasLoginProfile guard would make the "false" case fire — but it
// must NOT. The nil case proves the coalesce default keeps pre-enricher / call-failed graphs
// behaving as today. Driving the false node through NodeFromGaadUser is the regression guard
// against the omitempty bug (a confirmed false MUST land on the node, not be dropped).
func TestPrivescLoginProfileGuard(t *testing.T) {
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

	const (
		attacker = "arn:aws:iam::123456789012:user/lp-attacker"
		victim   = "arn:aws:iam::123456789012:user/lp-victim"
	)
	const queryID = "aws/enrich/privesc/iam_update_login_profile"

	bptr := func(b bool) *bool { return &b }

	edgeCount := func(t *testing.T, db graph.GraphDatabase) int64 {
		t.Helper()
		result, err := db.Query(ctx, fmt.Sprintf(
			`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(v {Arn: '%s'}) RETURN count(r) AS n`,
			attacker, victim), nil)
		require.NoError(t, err)
		n, _ := toInt64(result.Records[0]["n"])
		return n
	}

	cases := []struct {
		name            string
		hasLoginProfile *bool
		wantEdge        bool
		desc            string
	}{
		{
			name:            "no_profile_no_edge",
			hasLoginProfile: bptr(false),
			wantEdge:        false,
			desc:            "victim has no console login profile (confirmed false survives NodeFromGaadUser) → UpdateLoginProfile → NoSuchEntity → NO edge",
		},
		{
			name:            "has_profile_edge",
			hasLoginProfile: bptr(true),
			wantEdge:        true,
			desc:            "victim has an existing console login profile → UpdateLoginProfile resets it → edge fires",
		},
		{
			name:            "profile_unknown_failopen",
			hasLoginProfile: nil,
			wantEdge:        true,
			desc:            "HasLoginProfile nil (call not made/failed) → null → dropped → ABSENT → coalesce default true → FAIL-OPEN → edge fires as before",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := newAdapter(t)
			_, err := db.Query(ctx, "MATCH (n) DETACH DELETE n", nil)
			require.NoError(t, err)

			// Build the victim node through the production transformer so a confirmed
			// HasLoginProfile=false actually serializes onto the node (the omitempty bug
			// would have dropped it). _is_admin is set after CreateNodes since it is an
			// enricher-derived prop, not a GAAD field.
			victimNode := transformaws.NodeFromGaadUser(types.UserDetail{
				Arn:             victim,
				UserName:        "lp-victim",
				HasLoginProfile: tc.hasLoginProfile,
			})
			_, err = db.CreateNodes(ctx, []*graph.Node{victimNode})
			require.NoError(t, err, "write transformer-built victim node")

			_, err = db.Query(ctx, fmt.Sprintf(`
				MATCH (v:User {Arn: '%s'}) SET v._is_admin = true
				CREATE (a:User:Principal {Arn: '%s', _is_admin: false})
				MERGE (a)-[:IAM_UPDATELOGINPROFILE]->(v)
			`, victim, attacker), nil)
			require.NoError(t, err, "seed attacker + edge")

			_, err = RunPlatformQuery(ctx, db, queryID, nil)
			require.NoError(t, err, "run %s", queryID)

			n := edgeCount(t, db)
			if tc.wantEdge {
				assert.GreaterOrEqual(t, n, int64(1), tc.desc)
			} else {
				assert.Equal(t, int64(0), n, tc.desc)
			}
		})
	}
}

// TestPrivescPolicyVersionCountGuard locks down the <5-versions precondition for
// iam_create_policy_version. The transformer surfaces policy.policy_version_count; the method:
//   - count = 5     → NO edge (CreatePolicyVersion fails at the 5-version limit).
//   - count < 5     → edge fires (self-loop).
//   - count ABSENT  → FAIL-OPEN → edge fires as before (pre-enricher graph).
//
// Non-vacuous: dropping the <5 guard would make the count=5 case fire — but it must NOT.
func TestPrivescPolicyVersionCountGuard(t *testing.T) {
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

	const (
		attacker  = "arn:aws:iam::123456789012:user/pv-attacker"
		policyARN = "arn:aws:iam::123456789012:policy/pv-custom"
	)
	const queryID = "aws/enrich/privesc/iam_create_policy_version"

	// The attacker holds the customer-managed policy (AttachedManagedPolicies CONTAINS its ARN)
	// and IAM_CREATEPOLICYVERSION on it; policyProps sets/omits policy_version_count.
	setup := func(policyProps string) string {
		return fmt.Sprintf(`
			CREATE (a:User:Principal {Arn: '%s', _is_admin: false,
				AttachedManagedPolicies: '[{"PolicyArn":"%s"}]'})
			CREATE (p:Resource {Arn: '%s'%s})
			WITH a, p
			MERGE (a)-[:IAM_CREATEPOLICYVERSION]->(p)
		`, attacker, policyARN, policyARN, policyProps)
	}

	// iam_create_policy_version is a self-loop (attacker → attacker).
	edgeCount := func(t *testing.T, db graph.GraphDatabase) int64 {
		t.Helper()
		result, err := db.Query(ctx, fmt.Sprintf(
			`MATCH (a {Arn: '%s'})-[r:CAN_PRIVESC]->(a) RETURN count(r) AS n`, attacker), nil)
		require.NoError(t, err)
		n, _ := toInt64(result.Records[0]["n"])
		return n
	}

	cases := []struct {
		name        string
		policyProps string
		wantEdge    bool
		desc        string
	}{
		{
			name:        "five_versions_no_edge",
			policyProps: ", policy_version_count: 5",
			wantEdge:    false,
			desc:        "policy already has 5 versions → CreatePolicyVersion fails at the limit → NO edge",
		},
		{
			name:        "under_five_versions_edge",
			policyProps: ", policy_version_count: 4",
			wantEdge:    true,
			desc:        "policy has <5 versions → CreatePolicyVersion succeeds → self-loop edge fires",
		},
		{
			name:        "count_absent_failopen",
			policyProps: "",
			wantEdge:    true,
			desc:        "policy_version_count absent (pre-enricher graph) → FAIL-OPEN → edge fires as before",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := newAdapter(t)
			_, err := db.Query(ctx, "MATCH (n) DETACH DELETE n", nil)
			require.NoError(t, err)
			_, err = db.Query(ctx, setup(tc.policyProps), nil)
			require.NoError(t, err, "seed")

			_, err = RunPlatformQuery(ctx, db, queryID, nil)
			require.NoError(t, err, "run %s", queryID)

			n := edgeCount(t, db)
			if tc.wantEdge {
				assert.GreaterOrEqual(t, n, int64(1), tc.desc)
			} else {
				assert.Equal(t, int64(0), n, tc.desc)
			}
		})
	}
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
