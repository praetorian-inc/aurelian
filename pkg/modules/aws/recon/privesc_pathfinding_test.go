//go:build integration

package recon

import (
	"context"
	"fmt"
	"regexp"
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
//
//	lab_<plabs_id_underscored>_arn  for TP users
//	lab_fp_<description>_arn        for FP users (missing one or more required permissions)
var pathfindingLabCases = []labTestCase{

	// =========================================================================
	// TRUE POSITIVE cases — attacker has exactly the right permissions
	// =========================================================================

	{"lab_amplify_001_arn", "aws/enrich/privesc/amplify_create_app", true, "amplify-001: iam:PassRole+amplify:CreateApp → amplify_create_app must fire"},
	{"lab_apprunner_001_arn", "aws/enrich/privesc/apprunner_create_service", true, "apprunner-001: iam:PassRole+apprunner:CreateService → apprunner_create_service must fire"},
	{"lab_apprunner_002_arn", "aws/enrich/privesc/apprunner_update_service", true, "apprunner-002: apprunner:UpdateService → apprunner_update_service must fire"},
	{"lab_batch_001_arn", "aws/enrich/privesc/batch_passrole", true, "batch-001: iam:PassRole+batch:RegisterJobDefinition → batch_passrole must fire"},
	{"lab_batch_002_arn", "aws/enrich/privesc/batch_submit_job", true, "batch-002: batch:SubmitJob → batch_submit_job must fire"},
	{"lab_bedrock_001_arn", "aws/enrich/privesc/bedrock_create_code_interpreter", true, "bedrock-001: iam:PassRole+bedrock-agentcore:CreateCodeInterpreter → bedrock_create_code_interpreter must fire"},
	{"lab_bedrock_002_arn", "aws/enrich/privesc/bedrock_access_code_interpreter", true, "bedrock-002: bedrock-agentcore:InvokeSession → bedrock_access_code_interpreter must fire"},
	{"lab_braket_001_arn", "aws/enrich/privesc/braket_create_job", true, "braket-001: iam:PassRole+braket:CreateJob → braket_create_job must fire"},
	{"lab_cloudformation_001_arn", "aws/enrich/privesc/iam_pass_role_cloudformation", true, "cloudformation-001: iam:PassRole+cloudformation:CreateStack → iam_pass_role_cloudformation must fire"},
	{"lab_cloudformation_002_arn", "aws/enrich/privesc/cloudformation_update_stack", true, "cloudformation-002: cloudformation:UpdateStack → cloudformation_update_stack must fire"},
	{"lab_cloudformation_003_arn", "aws/enrich/privesc/cloudformation_create_stackset", true, "cloudformation-003: iam:PassRole+cloudformation:CreateStackSet → cloudformation_create_stackset must fire"},
	{"lab_cloudformation_004_arn", "aws/enrich/privesc/cloudformation_update_stackset", true, "cloudformation-004: iam:PassRole+cloudformation:UpdateStackSet → cloudformation_update_stackset must fire"},
	{"lab_cloudformation_005_arn", "aws/enrich/privesc/cloudformation_changeset", true, "cloudformation-005: cloudformation:CreateChangeSet+cloudformation:ExecuteChangeSet → cloudformation_changeset must fire"},
	{"lab_codebuild_001_arn", "aws/enrich/privesc/codebuild_create_project", true, "codebuild-001: iam:PassRole+codebuild:CreateProject → codebuild_create_project must fire"},
	{"lab_codebuild_002_arn", "aws/enrich/privesc/codebuild_start_build", true, "codebuild-002: codebuild:StartBuild → codebuild_start_build must fire"},
	{"lab_codebuild_003_arn", "aws/enrich/privesc/codebuild_start_build", true, "codebuild-003: codebuild:StartBuildBatch → codebuild_start_build must fire"},
	{"lab_codebuild_004_arn", "aws/enrich/privesc/codebuild_create_project", true, "codebuild-004: iam:PassRole+codebuild:CreateProject → codebuild_create_project must fire"},
	{"lab_codedeploy_001_arn", "aws/enrich/privesc/codedeploy_create_deployment", true, "codedeploy-001: codedeploy:CreateDeployment → codedeploy_create_deployment must fire"},
	{"lab_cognito_identity_001_arn", "aws/enrich/privesc/cognito_set_identity_pool_roles", true, "cognito-identity-001: iam:PassRole+cognito-identity:SetIdentityPoolRoles → cognito_set_identity_pool_roles must fire"},
	{"lab_ec2_001_arn", "aws/enrich/privesc/iam_pass_role_ec2", true, "ec2-001: iam:PassRole+ec2:RunInstances → iam_pass_role_ec2 must fire"},
	{"lab_ec2_002_arn", "aws/enrich/privesc/ec2_modify_instance_attribute", true, "ec2-002: ec2:ModifyInstanceAttribute+ec2:StopInstances → ec2_modify_instance_attribute must fire"},
	{"lab_ec2_003_arn", "aws/enrich/privesc/ec2_instance_connect", true, "ec2-003: ec2-instance-connect:SendSSHPublicKey → ec2_instance_connect must fire"},
	{"lab_ec2_004_arn", "aws/enrich/privesc/ec2_request_spot_instances", true, "ec2-004: iam:PassRole+ec2:RequestSpotInstances → ec2_request_spot_instances must fire"},
	{"lab_ec2_005_arn", "aws/enrich/privesc/ec2_launch_template_version", true, "ec2-005: ec2:CreateLaunchTemplateVersion+ec2:ModifyLaunchTemplate → ec2_launch_template_version must fire"},
	{"lab_ecs_001_arn", "aws/enrich/privesc/ecs_create_service", true, "ecs-001: iam:PassRole+ecs:CreateCluster → ecs_create_service must fire"},
	{"lab_ecs_002_arn", "aws/enrich/privesc/ecs_passrole_runtask", true, "ecs-002: iam:PassRole+ecs:CreateCluster → ecs_passrole_runtask must fire"},
	{"lab_ecs_003_arn", "aws/enrich/privesc/ecs_create_service", true, "ecs-003: iam:PassRole+ecs:RegisterTaskDefinition → ecs_create_service must fire"},
	{"lab_ecs_004_arn", "aws/enrich/privesc/ecs_passrole_runtask", true, "ecs-004: iam:PassRole+ecs:RegisterTaskDefinition → ecs_passrole_runtask must fire"},
	{"lab_ecs_005_arn", "aws/enrich/privesc/ecs_start_task", true, "ecs-005: iam:PassRole+ecs:RegisterTaskDefinition → ecs_start_task must fire"},
	{"lab_ecs_006_arn", "aws/enrich/privesc/ecs_execute_command", true, "ecs-006: ecs:ExecuteCommand+ecs:DescribeTasks → ecs_execute_command must fire"},
	{"lab_ecs_007_arn", "aws/enrich/privesc/ecs_start_task", true, "ecs-007: iam:PassRole+ecs:StartTask → ecs_start_task must fire"},
	{"lab_ecs_008_arn", "aws/enrich/privesc/ecs_passrole_runtask", true, "ecs-008: iam:PassRole+ecs:RunTask → ecs_passrole_runtask must fire"},
	{"lab_ecs_009_arn", "aws/enrich/privesc/ecs_start_task", true, "ecs-009: iam:PassRole+ecs:StartTask → ecs_start_task must fire"},
	{"lab_emr_001_arn", "aws/enrich/privesc/emr_run_job_flow", true, "emr-001: iam:PassRole+elasticmapreduce:RunJobFlow → emr_run_job_flow must fire"},
	{"lab_emr_serverless_001_arn", "aws/enrich/privesc/emr_serverless_startjobrun", true, "emr-serverless-001: iam:PassRole+emr-serverless:CreateApplication → emr_serverless_startjobrun must fire"},
	{"lab_gamelift_001_arn", "aws/enrich/privesc/gamelift_createbuild_createfleet", true, "gamelift-001: iam:PassRole+gamelift:CreateBuild → gamelift_createbuild_createfleet must fire"},
	{"lab_glue_001_arn", "aws/enrich/privesc/glue_create_dev_endpoint", true, "glue-001: iam:PassRole+glue:CreateDevEndpoint → glue_create_dev_endpoint must fire"},
	{"lab_glue_002_arn", "aws/enrich/privesc/glue_update_dev_endpoint", true, "glue-002: glue:UpdateDevEndpoint → glue_update_dev_endpoint must fire"},
	{"lab_glue_003_arn", "aws/enrich/privesc/glue_createjob_startjobrun", true, "glue-003: iam:PassRole+glue:CreateJob → glue_createjob_startjobrun must fire"},
	{"lab_glue_004_arn", "aws/enrich/privesc/glue_createjob_createtrigger", true, "glue-004: iam:PassRole+glue:CreateJob → glue_createjob_createtrigger must fire"},
	{"lab_glue_005_arn", "aws/enrich/privesc/glue_updatejob_startjobrun", true, "glue-005: iam:PassRole+glue:UpdateJob → glue_updatejob_startjobrun must fire"},
	{"lab_glue_006_arn", "aws/enrich/privesc/glue_updatejob_createtrigger", true, "glue-006: iam:PassRole+glue:UpdateJob → glue_updatejob_createtrigger must fire"},
	{"lab_glue_007_arn", "aws/enrich/privesc/glue_createsession_runstatement", true, "glue-007: iam:PassRole+glue:CreateSession → glue_createsession_runstatement must fire"},
	{"lab_iam_001_arn", "aws/enrich/privesc/iam_create_policy_version", true, "iam-001: iam:CreatePolicyVersion → iam_create_policy_version must fire"},
	{"lab_iam_002_arn", "aws/enrich/privesc/iam_create_access_key", true, "iam-002: iam:CreateAccessKey → iam_create_access_key must fire"},
	{"lab_iam_003_arn", "aws/enrich/privesc/iam_create_access_key", true, "iam-003: iam:DeleteAccessKey+iam:CreateAccessKey → iam_create_access_key must fire"},
	{"lab_iam_004_arn", "aws/enrich/privesc/iam_create_login_profile", true, "iam-004: iam:CreateLoginProfile → iam_create_login_profile must fire"},
	{"lab_iam_005_arn", "aws/enrich/privesc/iam_put_role_policy", true, "iam-005: iam:PutRolePolicy → iam_put_role_policy must fire"},
	{"lab_iam_006_arn", "aws/enrich/privesc/iam_update_login_profile", true, "iam-006: iam:UpdateLoginProfile → iam_update_login_profile must fire"},
	{"lab_iam_007_arn", "aws/enrich/privesc/iam_put_user_policy", true, "iam-007: iam:PutUserPolicy → iam_put_user_policy must fire"},
	{"lab_iam_008_arn", "aws/enrich/privesc/iam_attach_user_policy", true, "iam-008: iam:AttachUserPolicy → iam_attach_user_policy must fire"},
	{"lab_iam_009_arn", "aws/enrich/privesc/iam_attach_role_policy", true, "iam-009: iam:AttachRolePolicy → iam_attach_role_policy must fire"},
	{"lab_iam_010_arn", "aws/enrich/privesc/iam_attach_group_policy", true, "iam-010: iam:AttachGroupPolicy → iam_attach_group_policy must fire"},
	{"lab_iam_011_arn", "aws/enrich/privesc/iam_put_group_policy", true, "iam-011: iam:PutGroupPolicy → iam_put_group_policy must fire"},
	{"lab_iam_012_arn", "aws/enrich/privesc/iam_update_assume_role_policy", true, "iam-012: iam:UpdateAssumeRolePolicy → iam_update_assume_role_policy must fire"},
	{"lab_iam_013_arn", "aws/enrich/privesc/iam_add_user_to_group", true, "iam-013: iam:AddUserToGroup → iam_add_user_to_group must fire"},
	{"lab_iam_014_arn", "aws/enrich/privesc/iam_attach_role_policy", true, "iam-014: iam:AttachRolePolicy+sts:AssumeRole → iam_attach_role_policy must fire"},
	{"lab_iam_015_arn", "aws/enrich/privesc/iam_attach_user_policy", true, "iam-015: iam:AttachUserPolicy+iam:CreateAccessKey → iam_attach_user_policy must fire"},
	{"lab_iam_016_arn", "aws/enrich/privesc/iam_create_policy_version", true, "iam-016: iam:CreatePolicyVersion+sts:AssumeRole → iam_create_policy_version must fire"},
	{"lab_iam_017_arn", "aws/enrich/privesc/iam_put_role_policy", true, "iam-017: iam:PutRolePolicy+sts:AssumeRole → iam_put_role_policy must fire"},
	{"lab_iam_018_arn", "aws/enrich/privesc/iam_put_user_policy", true, "iam-018: iam:PutUserPolicy+iam:CreateAccessKey → iam_put_user_policy must fire"},
	{"lab_iam_019_arn", "aws/enrich/privesc/passrole_modify_policy", true, "iam-019: iam:AttachRolePolicy+iam:UpdateAssumeRolePolicy → passrole_modify_policy must fire"},
	{"lab_iam_020_arn", "aws/enrich/privesc/update_assume_role_passrole_service", true, "iam-020: iam:CreatePolicyVersion+iam:UpdateAssumeRolePolicy → update_assume_role_passrole_service must fire"},
	{"lab_iam_021_arn", "aws/enrich/privesc/update_assume_role_passrole_service", true, "iam-021: iam:PutRolePolicy+iam:UpdateAssumeRolePolicy → update_assume_role_passrole_service must fire"},
	{"lab_imagebuilder_001_arn", "aws/enrich/privesc/imagebuilder_createimage", true, "imagebuilder-001: iam:PassRole+imagebuilder:CreateInfrastructureConfiguration → imagebuilder_createimage must fire"},
	{"lab_kinesisanalytics_001_arn", "aws/enrich/privesc/kinesisanalytics_startapplication", true, "kinesisanalytics-001: iam:PassRole+kinesisanalytics:CreateApplication → kinesisanalytics_startapplication must fire"},
	{"lab_lambda_001_arn", "aws/enrich/privesc/iam_pass_role_lambda", true, "lambda-001: iam:PassRole+lambda:CreateFunction → iam_pass_role_lambda must fire"},
	{"lab_lambda_002_arn", "aws/enrich/privesc/iam_pass_role_lambda", true, "lambda-002: iam:PassRole+lambda:CreateFunction → iam_pass_role_lambda must fire"},
	{"lab_lambda_003_arn", "aws/enrich/privesc/lambda_update_function_code", true, "lambda-003: lambda:UpdateFunctionCode → lambda_update_function_code must fire"},
	{"lab_lambda_004_arn", "aws/enrich/privesc/lambda_updatecode_invoke", true, "lambda-004: lambda:UpdateFunctionCode+lambda:InvokeFunction → lambda_updatecode_invoke must fire"},
	{"lab_lambda_005_arn", "aws/enrich/privesc/lambda_add_permission", true, "lambda-005: lambda:UpdateFunctionCode+lambda:AddPermission → lambda_add_permission must fire"},
	{"lab_lambda_006_arn", "aws/enrich/privesc/lambda_passrole_createfunction_addpermission", true, "lambda-006: iam:PassRole+lambda:CreateFunction → lambda_passrole_createfunction_addpermission must fire"},
	{"lab_omics_001_arn", "aws/enrich/privesc/omics_startrun", true, "omics-001: iam:PassRole+omics:CreateWorkflow → omics_startrun must fire"},
	{"lab_sagemaker_001_arn", "aws/enrich/privesc/iam_pass_role_sagemaker", true, "sagemaker-001: iam:PassRole+sagemaker:CreateNotebookInstance → iam_pass_role_sagemaker must fire"},
	{"lab_sagemaker_002_arn", "aws/enrich/privesc/sagemaker_training_job", true, "sagemaker-002: iam:PassRole+sagemaker:CreateTrainingJob → sagemaker_training_job must fire"},
	{"lab_sagemaker_003_arn", "aws/enrich/privesc/sagemaker_processing_job", true, "sagemaker-003: iam:PassRole+sagemaker:CreateProcessingJob → sagemaker_processing_job must fire"},
	{"lab_sagemaker_004_arn", "aws/enrich/privesc/sagemaker_presigned_url", true, "sagemaker-004: sagemaker:CreatePresignedNotebookInstanceUrl → sagemaker_presigned_url must fire"},
	{"lab_sagemaker_005_arn", "aws/enrich/privesc/sagemaker_lifecycle_config", true, "sagemaker-005: sagemaker:UpdateNotebookInstanceLifecycleConfig → sagemaker_lifecycle_config must fire"},
	{"lab_scheduler_001_arn", "aws/enrich/privesc/scheduler_create_schedule", true, "scheduler-001: iam:PassRole+scheduler:CreateSchedule → scheduler_create_schedule must fire"},
	{"lab_ssm_001_arn", "aws/enrich/privesc/ssm_start_session", true, "ssm-001: ssm:StartSession → ssm_start_session must fire"},
	{"lab_ssm_002_arn", "aws/enrich/privesc/ssm_send_command", true, "ssm-002: ssm:SendCommand → ssm_send_command must fire"},
	{"lab_ssm_003_arn", "aws/enrich/privesc/ssm_createdocument_startautomation", true, "ssm-003: ssm:CreateDocument+ssm:StartAutomationExecution → ssm_createdocument_startautomation must fire"},
	{"lab_stepfunctions_001_arn", "aws/enrich/privesc/stepfunctions_create_startexecution", true, "stepfunctions-001: iam:PassRole+states:CreateStateMachine → stepfunctions_create_startexecution must fire"},
	{"lab_stepfunctions_002_arn", "aws/enrich/privesc/stepfunctions_update", true, "stepfunctions-002: states:UpdateStateMachine+states:StartExecution → stepfunctions_update must fire"},
	{"lab_sts_001_arn", "aws/enrich/privesc/sts_assume_role", true, "sts-001: sts:AssumeRole → sts_assume_role must fire"},

	// =========================================================================
	// FALSE POSITIVE cases — attacker is MISSING one or more required permissions
	// The named method must NOT fire (0 CAN_PRIVESC edges).
	// =========================================================================

	// PassRole alone — no service action
	// Every PassRole+service method (14,15,16,17,18,19,32,43,45,47,48,49,...) must NOT fire.
	{"lab_fp_passrole_only_arn", "aws/enrich/privesc/iam_pass_role_lambda", false,
		"PassRole alone (no CreateFunction/InvokeFunction) → iam_pass_role_lambda must NOT fire"},
	{"lab_fp_passrole_only_arn", "aws/enrich/privesc/iam_pass_role_ec2", false,
		"PassRole alone (no RunInstances) → iam_pass_role_ec2 must NOT fire"},
	{"lab_fp_passrole_only_arn", "aws/enrich/privesc/iam_pass_role_cloudformation", false,
		"PassRole alone (no CreateStack) → iam_pass_role_cloudformation must NOT fire"},
	{"lab_fp_passrole_only_arn", "aws/enrich/privesc/ec2_request_spot_instances", false,
		"PassRole alone (no RequestSpotInstances) → ec2_request_spot_instances must NOT fire"},

	// Lambda: one permission present, other absent
	{"lab_fp_lambda_createfunction_only_arn", "aws/enrich/privesc/iam_pass_role_lambda", false,
		"CreateFunction alone (no PassRole, no InvokeFunction) → iam_pass_role_lambda must NOT fire"},
	{"lab_fp_lambda_invoke_only_arn", "aws/enrich/privesc/iam_pass_role_lambda", false,
		"InvokeFunction alone (no PassRole, no CreateFunction) → iam_pass_role_lambda must NOT fire"},
	{"lab_fp_lambda_004_no_invoke_arn", "aws/enrich/privesc/lambda_updatecode_invoke", false,
		"UpdateFunctionCode alone (no InvokeFunction) → lambda_updatecode_invoke (compound) must NOT fire"},

	// EC2: service action present but PassRole missing
	{"lab_fp_ec2_runinstances_only_arn", "aws/enrich/privesc/iam_pass_role_ec2", false,
		"ec2:RunInstances alone (no PassRole) → iam_pass_role_ec2 must NOT fire"},

	// CloudFormation: CreateStack without PassRole
	{"lab_fp_cfn_createstack_only_arn", "aws/enrich/privesc/iam_pass_role_cloudformation", false,
		"cloudformation:CreateStack alone (no PassRole) → iam_pass_role_cloudformation must NOT fire"},

	// Glue: missing execution permission
	{"lab_fp_glue_createjob_only_arn", "aws/enrich/privesc/glue_createjob_startjobrun", false,
		"glue:CreateJob alone (no PassRole, no StartJobRun) → glue_createjob_startjobrun must NOT fire"},
	{"lab_fp_glue_passrole_createjob_nostartjobrun_arn", "aws/enrich/privesc/glue_createjob_startjobrun", false,
		"PassRole + CreateJob (no StartJobRun) → glue_createjob_startjobrun must NOT fire (needs all 3)"},

	// Step Functions: CreateStateMachine without StartExecution
	{"lab_fp_sfn_no_startexecution_arn", "aws/enrich/privesc/stepfunctions_create_startexecution", false,
		"PassRole + CreateStateMachine (no StartExecution) → stepfunctions_create_startexecution must NOT fire"},
	// stepfunctions_create only requires PassRole+CreateStateMachine — should still fire
	{"lab_fp_sfn_no_startexecution_arn", "aws/enrich/privesc/stepfunctions_create", true,
		"PassRole + CreateStateMachine (no StartExecution) → stepfunctions_create SHOULD fire (no StartExecution needed)"},

	// ECS: CreateService without PassRole
	{"lab_fp_ecs_createservice_only_arn", "aws/enrich/privesc/ecs_create_service", false,
		"ecs:CreateService alone (no PassRole) → ecs_create_service must NOT fire"},

	// EMR Serverless: CreateApplication without StartJobRun
	{"lab_fp_emr_serverless_no_startjobrun_arn", "aws/enrich/privesc/emr_serverless_startjobrun", false,
		"PassRole + CreateApplication (no StartJobRun) → emr_serverless_startjobrun must NOT fire"},
	// emr_serverless only requires PassRole+CreateApplication — should still fire
	{"lab_fp_emr_serverless_no_startjobrun_arn", "aws/enrich/privesc/emr_serverless", true,
		"PassRole + CreateApplication (no StartJobRun) → emr_serverless SHOULD fire (no StartJobRun needed)"},

	// SSM: CreateDocument without StartAutomationExecution
	{"lab_fp_ssm_createdoc_only_arn", "aws/enrich/privesc/ssm_createdocument_startautomation", false,
		"ssm:CreateDocument alone (no StartAutomationExecution) → ssm_createdocument_startautomation must NOT fire"},

	// Lambda compound methods: missing second permission
	{"lab_fp_lambda_004_no_invoke_arn", "aws/enrich/privesc/lambda_updatecode_invoke", false,
		"UpdateFunctionCode alone → lambda_updatecode_invoke must NOT fire"},
	{"lab_fp_lambda_005_no_addpermission_arn", "aws/enrich/privesc/lambda_add_permission", false,
		"UpdateFunctionCode alone → lambda_add_permission must NOT fire"},

	// Glue: PassRole alone without CreateDevEndpoint
	{"lab_fp_glue_001_no_createdevendpoint_arn", "aws/enrich/privesc/glue_create_dev_endpoint", false,
		"PassRole alone → glue_create_dev_endpoint must NOT fire"},

	// ECS: RunTask without PassRole
	{"lab_fp_ecs_runtask_no_passrole_arn", "aws/enrich/privesc/ecs_passrole_runtask", false,
		"ecs:RunTask alone → ecs_passrole_runtask must NOT fire"},

	// EMR: RunJobFlow without PassRole
	{"lab_fp_emr_runjobflow_no_passrole_arn", "aws/enrich/privesc/emr_run_job_flow", false,
		"elasticmapreduce:RunJobFlow alone → emr_run_job_flow must NOT fire"},

	// SSM: StartAutomationExecution alone
	{"lab_fp_ssm_startautomation_only_arn", "aws/enrich/privesc/ssm_createdocument_startautomation", false,
		"ssm:StartAutomationExecution alone → ssm_createdocument_startautomation must NOT fire"},

	// Step Functions: UpdateStateMachine alone
	{"lab_fp_sfn_updatestatemachine_only_arn", "aws/enrich/privesc/stepfunctions_update", false,
		"states:UpdateStateMachine alone → stepfunctions_update must NOT fire"},
}

// peMethodLiteral extracts the human-readable method string a privesc query
// stamps onto its CAN_PRIVESC edge (e.g. "iam:PassRole + lambda:CreateFunction").
// FP assertions match this exact value rather than the query-ID slug, because the
// edge's r.method property stores the human-readable string — matching the slug
// would never match, making the FP check vacuous. Reading it from the loaded
// query's Cypher keeps the test in sync with the YAML rather than a hardcoded map.
//
// CAN_PRIVESC is now a multi-edge relationship: `method` lives in the MERGE
// relationship pattern (`MERGE (a)-[pe:CAN_PRIVESC {method: '<M>'}]->(t)`), not in
// a `SET pe.method = '<M>'` clause, so we match the `{method: '<M>'}` literal.
var peMethodRe = regexp.MustCompile(`CAN_PRIVESC\s*\{method:\s*'([^']*)'\}`)

func peMethodLiteral(methodID string) (string, bool) {
	q, ok := queries.GetQuery(methodID)
	if !ok {
		return "", false
	}
	m := peMethodRe.FindStringSubmatch(q.Cypher)
	if len(m) != 2 {
		return "", false
	}
	return m[1], true
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
		// TP lab users
		"lab_amplify_001_arn",
		"lab_apprunner_001_arn",
		"lab_apprunner_002_arn",
		"lab_batch_001_arn",
		"lab_batch_002_arn",
		"lab_bedrock_001_arn",
		"lab_bedrock_002_arn",
		"lab_braket_001_arn",
		"lab_cloudformation_001_arn",
		"lab_cloudformation_002_arn",
		"lab_cloudformation_003_arn",
		"lab_cloudformation_004_arn",
		"lab_cloudformation_005_arn",
		"lab_codebuild_001_arn",
		"lab_codebuild_002_arn",
		"lab_codebuild_003_arn",
		"lab_codebuild_004_arn",
		"lab_codedeploy_001_arn",
		"lab_cognito_identity_001_arn",
		"lab_ec2_001_arn",
		"lab_ec2_002_arn",
		"lab_ec2_003_arn",
		"lab_ec2_004_arn",
		"lab_ec2_005_arn",
		"lab_ecs_001_arn",
		"lab_ecs_002_arn",
		"lab_ecs_003_arn",
		"lab_ecs_004_arn",
		"lab_ecs_005_arn",
		"lab_ecs_006_arn",
		"lab_ecs_007_arn",
		"lab_ecs_008_arn",
		"lab_ecs_009_arn",
		"lab_emr_001_arn",
		"lab_emr_serverless_001_arn",
		"lab_gamelift_001_arn",
		"lab_glue_001_arn",
		"lab_glue_002_arn",
		"lab_glue_003_arn",
		"lab_glue_004_arn",
		"lab_glue_005_arn",
		"lab_glue_006_arn",
		"lab_glue_007_arn",
		"lab_iam_001_arn",
		"lab_iam_002_arn",
		"lab_iam_003_arn",
		"lab_iam_004_arn",
		"lab_iam_005_arn",
		"lab_iam_006_arn",
		"lab_iam_007_arn",
		"lab_iam_008_arn",
		"lab_iam_009_arn",
		"lab_iam_010_arn",
		"lab_iam_011_arn",
		"lab_iam_012_arn",
		"lab_iam_013_arn",
		"lab_iam_014_arn",
		"lab_iam_015_arn",
		"lab_iam_016_arn",
		"lab_iam_017_arn",
		"lab_iam_018_arn",
		"lab_iam_019_arn",
		"lab_iam_020_arn",
		"lab_iam_021_arn",
		"lab_imagebuilder_001_arn",
		"lab_kinesisanalytics_001_arn",
		"lab_lambda_001_arn",
		"lab_lambda_002_arn",
		"lab_lambda_003_arn",
		"lab_lambda_004_arn",
		"lab_lambda_005_arn",
		"lab_lambda_006_arn",
		"lab_omics_001_arn",
		"lab_sagemaker_001_arn",
		"lab_sagemaker_002_arn",
		"lab_sagemaker_003_arn",
		"lab_sagemaker_004_arn",
		"lab_sagemaker_005_arn",
		"lab_scheduler_001_arn",
		"lab_ssm_001_arn",
		"lab_ssm_002_arn",
		"lab_ssm_003_arn",
		"lab_stepfunctions_001_arn",
		"lab_stepfunctions_002_arn",
		"lab_sts_001_arn",
		// FP lab users (existing)
		"lab_fp_passrole_only_arn",
		"lab_fp_lambda_createfunction_only_arn",
		"lab_fp_lambda_invoke_only_arn",
		"lab_fp_lambda_004_no_invoke_arn",
		"lab_fp_ec2_runinstances_only_arn",
		"lab_fp_cfn_createstack_only_arn",
		"lab_fp_glue_createjob_only_arn",
		"lab_fp_glue_passrole_createjob_nostartjobrun_arn",
		"lab_fp_sfn_no_startexecution_arn",
		"lab_fp_ecs_createservice_only_arn",
		"lab_fp_emr_serverless_no_startjobrun_arn",
		"lab_fp_ssm_createdoc_only_arn",
		// FP lab users (new)
		"lab_fp_lambda_004_no_invoke_arn",
		"lab_fp_lambda_005_no_addpermission_arn",
		"lab_fp_glue_001_no_createdevendpoint_arn",
		"lab_fp_ecs_runtask_no_passrole_arn",
		"lab_fp_emr_runjobflow_no_passrole_arn",
		"lab_fp_ssm_startautomation_only_arn",
		"lab_fp_sfn_updatestatemachine_only_arn",
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

			// methodSuffix is the query-ID slug, used only for readable failure messages.
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
				// FP: the SPECIFIC method must not have fired for this attacker.
				// The CAN_PRIVESC edge stores a human-readable r.method (e.g.
				// "iam:PassRole + lambda:CreateFunction"), NOT the query-ID slug, so we
				// match the exact method literal the query stamps — read from its Cypher.
				// require() (not assert+skip) so a renamed/missing literal fails loud
				// rather than turning the FP check vacuous. Exact equality (not CONTAINS)
				// keeps the assertion sound: it fails iff THIS method fired. Other,
				// simpler methods may legitimately fire on the same attacker — expected
				// (e.g. lab_fp_sfn_no_startexecution also legitimately fires stepfunctions_create).
				//
				// With multi-edge CAN_PRIVESC (one edge per method) this check is now fully
				// SOUND: each method owns its own edge keyed by `method`, so r.method = $method
				// counts exactly THIS method's edge. Under the old single-edge model a
				// last-write-wins `method` could mask an earlier method's edge from this count.
				method, ok := peMethodLiteral(tc.methodID)
				require.True(t, ok,
					"could not extract pe.method literal for %s — FP check would be vacuous", tc.methodID)

				result, err := db.Query(ctx,
					`MATCH (a)-[r:CAN_PRIVESC]->()
					 WHERE (a.Arn = $arn OR a.arn = $arn)
					   AND r.method = $method
					 RETURN count(r) AS n`,
					map[string]any{"arn": attackerARN, "method": method})
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
					"[FP FAIL] %s (%s, method=%q) fired for %s — %s",
					tc.methodID, methodSuffix, method, attackerARN, tc.description)
			}
		})
	}
}
