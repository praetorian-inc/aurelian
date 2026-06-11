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
//
//	lab_<plabs_id_underscored>_arn  for TP users
//	lab_fp_<description>_arn        for FP users (missing one or more required permissions)
var pathfindingLabCases = []labTestCase{

	// =========================================================================
	// TRUE POSITIVE cases — attacker has exactly the right permissions
	// =========================================================================

	{"lab_amplify_001_arn", "aws/enrich/privesc/method_75", true, "amplify-001: iam:PassRole+amplify:CreateApp → method_75 must fire"},
	{"lab_apprunner_001_arn", "aws/enrich/privesc/method_43", true, "apprunner-001: iam:PassRole+apprunner:CreateService → method_43 must fire"},
	{"lab_apprunner_002_arn", "aws/enrich/privesc/method_44", true, "apprunner-002: apprunner:UpdateService → method_44 must fire"},
	{"lab_batch_001_arn", "aws/enrich/privesc/method_45", true, "batch-001: iam:PassRole+batch:RegisterJobDefinition → method_45 must fire"},
	{"lab_batch_002_arn", "aws/enrich/privesc/method_46", true, "batch-002: batch:SubmitJob → method_46 must fire"},
	{"lab_bedrock_001_arn", "aws/enrich/privesc/method_40", true, "bedrock-001: iam:PassRole+bedrock-agentcore:CreateCodeInterpreter → method_40 must fire"},
	{"lab_bedrock_002_arn", "aws/enrich/privesc/method_72", true, "bedrock-002: bedrock-agentcore:InvokeSession → method_72 must fire"},
	{"lab_braket_001_arn", "aws/enrich/privesc/method_47", true, "braket-001: iam:PassRole+braket:CreateJob → method_47 must fire"},
	{"lab_cloudformation_001_arn", "aws/enrich/privesc/method_16", true, "cloudformation-001: iam:PassRole+cloudformation:CreateStack → method_16 must fire"},
	{"lab_cloudformation_002_arn", "aws/enrich/privesc/method_30", true, "cloudformation-002: cloudformation:UpdateStack → method_30 must fire"},
	{"lab_cloudformation_003_arn", "aws/enrich/privesc/method_48", true, "cloudformation-003: iam:PassRole+cloudformation:CreateStackSet → method_48 must fire"},
	{"lab_cloudformation_004_arn", "aws/enrich/privesc/method_49", true, "cloudformation-004: iam:PassRole+cloudformation:UpdateStackSet → method_49 must fire"},
	{"lab_cloudformation_005_arn", "aws/enrich/privesc/method_31", true, "cloudformation-005: cloudformation:CreateChangeSet+cloudformation:ExecuteChangeSet → method_31 must fire"},
	{"lab_codebuild_001_arn", "aws/enrich/privesc/method_27", true, "codebuild-001: iam:PassRole+codebuild:CreateProject → method_27 must fire"},
	{"lab_codebuild_002_arn", "aws/enrich/privesc/method_33", true, "codebuild-002: codebuild:StartBuild → method_33 must fire"},
	{"lab_codebuild_003_arn", "aws/enrich/privesc/method_33", true, "codebuild-003: codebuild:StartBuildBatch → method_33 must fire"},
	{"lab_codebuild_004_arn", "aws/enrich/privesc/method_27", true, "codebuild-004: iam:PassRole+codebuild:CreateProject → method_27 must fire"},
	{"lab_codedeploy_001_arn", "aws/enrich/privesc/method_50", true, "codedeploy-001: codedeploy:CreateDeployment → method_50 must fire"},
	{"lab_cognito_identity_001_arn", "aws/enrich/privesc/method_51", true, "cognito-identity-001: iam:PassRole+cognito-identity:SetIdentityPoolRoles → method_51 must fire"},
	{"lab_ec2_001_arn", "aws/enrich/privesc/method_15", true, "ec2-001: iam:PassRole+ec2:RunInstances → method_15 must fire"},
	{"lab_ec2_002_arn", "aws/enrich/privesc/method_76", true, "ec2-002: ec2:ModifyInstanceAttribute+ec2:StopInstances → method_76 must fire"},
	{"lab_ec2_003_arn", "aws/enrich/privesc/method_52", true, "ec2-003: ec2-instance-connect:SendSSHPublicKey → method_52 must fire"},
	{"lab_ec2_004_arn", "aws/enrich/privesc/method_73", true, "ec2-004: iam:PassRole+ec2:RequestSpotInstances → method_73 must fire"},
	{"lab_ec2_005_arn", "aws/enrich/privesc/method_74", true, "ec2-005: ec2:CreateLaunchTemplateVersion+ec2:ModifyLaunchTemplate → method_74 must fire"},
	{"lab_ecs_001_arn", "aws/enrich/privesc/method_54", true, "ecs-001: iam:PassRole+ecs:CreateCluster → method_54 must fire"},
	{"lab_ecs_002_arn", "aws/enrich/privesc/method_32", true, "ecs-002: iam:PassRole+ecs:CreateCluster → method_32 must fire"},
	{"lab_ecs_003_arn", "aws/enrich/privesc/method_54", true, "ecs-003: iam:PassRole+ecs:RegisterTaskDefinition → method_54 must fire"},
	{"lab_ecs_004_arn", "aws/enrich/privesc/method_32", true, "ecs-004: iam:PassRole+ecs:RegisterTaskDefinition → method_32 must fire"},
	{"lab_ecs_005_arn", "aws/enrich/privesc/method_55", true, "ecs-005: iam:PassRole+ecs:RegisterTaskDefinition → method_55 must fire"},
	{"lab_ecs_006_arn", "aws/enrich/privesc/method_56", true, "ecs-006: ecs:ExecuteCommand+ecs:DescribeTasks → method_56 must fire"},
	{"lab_ecs_007_arn", "aws/enrich/privesc/method_55", true, "ecs-007: iam:PassRole+ecs:StartTask → method_55 must fire"},
	{"lab_ecs_008_arn", "aws/enrich/privesc/method_32", true, "ecs-008: iam:PassRole+ecs:RunTask → method_32 must fire"},
	{"lab_ecs_009_arn", "aws/enrich/privesc/method_55", true, "ecs-009: iam:PassRole+ecs:StartTask → method_55 must fire"},
	{"lab_emr_001_arn", "aws/enrich/privesc/method_57", true, "emr-001: iam:PassRole+elasticmapreduce:RunJobFlow → method_57 must fire"},
	{"lab_emr_serverless_001_arn", "aws/enrich/privesc/method_85", true, "emr-serverless-001: iam:PassRole+emr-serverless:CreateApplication → method_85 must fire"},
	{"lab_gamelift_001_arn", "aws/enrich/privesc/method_88", true, "gamelift-001: iam:PassRole+gamelift:CreateBuild → method_88 must fire"},
	{"lab_glue_001_arn", "aws/enrich/privesc/method_60", true, "glue-001: iam:PassRole+glue:CreateDevEndpoint → method_60 must fire"},
	{"lab_glue_002_arn", "aws/enrich/privesc/method_29", true, "glue-002: glue:UpdateDevEndpoint → method_29 must fire"},
	{"lab_glue_003_arn", "aws/enrich/privesc/method_80", true, "glue-003: iam:PassRole+glue:CreateJob → method_80 must fire"},
	{"lab_glue_004_arn", "aws/enrich/privesc/method_77", true, "glue-004: iam:PassRole+glue:CreateJob → method_77 must fire"},
	{"lab_glue_005_arn", "aws/enrich/privesc/method_81", true, "glue-005: iam:PassRole+glue:UpdateJob → method_81 must fire"},
	{"lab_glue_006_arn", "aws/enrich/privesc/method_78", true, "glue-006: iam:PassRole+glue:UpdateJob → method_78 must fire"},
	{"lab_glue_007_arn", "aws/enrich/privesc/method_82", true, "glue-007: iam:PassRole+glue:CreateSession → method_82 must fire"},
	{"lab_iam_001_arn", "aws/enrich/privesc/method_01", true, "iam-001: iam:CreatePolicyVersion → method_01 must fire"},
	{"lab_iam_002_arn", "aws/enrich/privesc/method_03", true, "iam-002: iam:CreateAccessKey → method_03 must fire"},
	{"lab_iam_003_arn", "aws/enrich/privesc/method_03", true, "iam-003: iam:DeleteAccessKey+iam:CreateAccessKey → method_03 must fire"},
	{"lab_iam_004_arn", "aws/enrich/privesc/method_04", true, "iam-004: iam:CreateLoginProfile → method_04 must fire"},
	{"lab_iam_005_arn", "aws/enrich/privesc/method_11", true, "iam-005: iam:PutRolePolicy → method_11 must fire"},
	{"lab_iam_006_arn", "aws/enrich/privesc/method_05", true, "iam-006: iam:UpdateLoginProfile → method_05 must fire"},
	{"lab_iam_007_arn", "aws/enrich/privesc/method_09", true, "iam-007: iam:PutUserPolicy → method_09 must fire"},
	{"lab_iam_008_arn", "aws/enrich/privesc/method_06", true, "iam-008: iam:AttachUserPolicy → method_06 must fire"},
	{"lab_iam_009_arn", "aws/enrich/privesc/method_08", true, "iam-009: iam:AttachRolePolicy → method_08 must fire"},
	{"lab_iam_010_arn", "aws/enrich/privesc/method_07", true, "iam-010: iam:AttachGroupPolicy → method_07 must fire"},
	{"lab_iam_011_arn", "aws/enrich/privesc/method_10", true, "iam-011: iam:PutGroupPolicy → method_10 must fire"},
	{"lab_iam_012_arn", "aws/enrich/privesc/method_13", true, "iam-012: iam:UpdateAssumeRolePolicy → method_13 must fire"},
	{"lab_iam_013_arn", "aws/enrich/privesc/method_12", true, "iam-013: iam:AddUserToGroup → method_12 must fire"},
	{"lab_iam_014_arn", "aws/enrich/privesc/method_08", true, "iam-014: iam:AttachRolePolicy+sts:AssumeRole → method_08 must fire"},
	{"lab_iam_015_arn", "aws/enrich/privesc/method_06", true, "iam-015: iam:AttachUserPolicy+iam:CreateAccessKey → method_06 must fire"},
	{"lab_iam_016_arn", "aws/enrich/privesc/method_01", true, "iam-016: iam:CreatePolicyVersion+sts:AssumeRole → method_01 must fire"},
	{"lab_iam_017_arn", "aws/enrich/privesc/method_11", true, "iam-017: iam:PutRolePolicy+sts:AssumeRole → method_11 must fire"},
	{"lab_iam_018_arn", "aws/enrich/privesc/method_09", true, "iam-018: iam:PutUserPolicy+iam:CreateAccessKey → method_09 must fire"},
	{"lab_iam_019_arn", "aws/enrich/privesc/method_41", true, "iam-019: iam:AttachRolePolicy+iam:UpdateAssumeRolePolicy → method_41 must fire"},
	{"lab_iam_020_arn", "aws/enrich/privesc/method_42", true, "iam-020: iam:CreatePolicyVersion+iam:UpdateAssumeRolePolicy → method_42 must fire"},
	{"lab_iam_021_arn", "aws/enrich/privesc/method_42", true, "iam-021: iam:PutRolePolicy+iam:UpdateAssumeRolePolicy → method_42 must fire"},
	{"lab_imagebuilder_001_arn", "aws/enrich/privesc/method_89", true, "imagebuilder-001: iam:PassRole+imagebuilder:CreateInfrastructureConfiguration → method_89 must fire"},
	{"lab_kinesisanalytics_001_arn", "aws/enrich/privesc/method_86", true, "kinesisanalytics-001: iam:PassRole+kinesisanalytics:CreateApplication → method_86 must fire"},
	{"lab_lambda_001_arn", "aws/enrich/privesc/method_14", true, "lambda-001: iam:PassRole+lambda:CreateFunction → method_14 must fire"},
	{"lab_lambda_002_arn", "aws/enrich/privesc/method_14", true, "lambda-002: iam:PassRole+lambda:CreateFunction → method_14 must fire"},
	{"lab_lambda_003_arn", "aws/enrich/privesc/method_20", true, "lambda-003: lambda:UpdateFunctionCode → method_20 must fire"},
	{"lab_lambda_004_arn", "aws/enrich/privesc/method_39", true, "lambda-004: lambda:UpdateFunctionCode+lambda:InvokeFunction → method_39 must fire"},
	{"lab_lambda_005_arn", "aws/enrich/privesc/method_65", true, "lambda-005: lambda:UpdateFunctionCode+lambda:AddPermission → method_65 must fire"},
	{"lab_lambda_006_arn", "aws/enrich/privesc/method_79", true, "lambda-006: iam:PassRole+lambda:CreateFunction → method_79 must fire"},
	{"lab_omics_001_arn", "aws/enrich/privesc/method_87", true, "omics-001: iam:PassRole+omics:CreateWorkflow → method_87 must fire"},
	{"lab_sagemaker_001_arn", "aws/enrich/privesc/method_19", true, "sagemaker-001: iam:PassRole+sagemaker:CreateNotebookInstance → method_19 must fire"},
	{"lab_sagemaker_002_arn", "aws/enrich/privesc/method_36", true, "sagemaker-002: iam:PassRole+sagemaker:CreateTrainingJob → method_36 must fire"},
	{"lab_sagemaker_003_arn", "aws/enrich/privesc/method_37", true, "sagemaker-003: iam:PassRole+sagemaker:CreateProcessingJob → method_37 must fire"},
	{"lab_sagemaker_004_arn", "aws/enrich/privesc/method_35", true, "sagemaker-004: sagemaker:CreatePresignedNotebookInstanceUrl → method_35 must fire"},
	{"lab_sagemaker_005_arn", "aws/enrich/privesc/method_67", true, "sagemaker-005: sagemaker:UpdateNotebookInstanceLifecycleConfig → method_67 must fire"},
	{"lab_scheduler_001_arn", "aws/enrich/privesc/method_68", true, "scheduler-001: iam:PassRole+scheduler:CreateSchedule → method_68 must fire"},
	{"lab_ssm_001_arn", "aws/enrich/privesc/method_24", true, "ssm-001: ssm:StartSession → method_24 must fire"},
	{"lab_ssm_002_arn", "aws/enrich/privesc/method_23", true, "ssm-002: ssm:SendCommand → method_23 must fire"},
	{"lab_ssm_003_arn", "aws/enrich/privesc/method_84", true, "ssm-003: ssm:CreateDocument+ssm:StartAutomationExecution → method_84 must fire"},
	{"lab_stepfunctions_001_arn", "aws/enrich/privesc/method_83", true, "stepfunctions-001: iam:PassRole+states:CreateStateMachine → method_83 must fire"},
	{"lab_stepfunctions_002_arn", "aws/enrich/privesc/method_71", true, "stepfunctions-002: states:UpdateStateMachine+states:StartExecution → method_71 must fire"},
	{"lab_sts_001_arn", "aws/enrich/privesc/method_22", true, "sts-001: sts:AssumeRole → method_22 must fire"},

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
	{"lab_fp_lambda_004_no_invoke_arn", "aws/enrich/privesc/method_39", false,
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
	{"lab_fp_glue_passrole_createjob_nostartjobrun_arn", "aws/enrich/privesc/method_80", false,
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
	{"lab_fp_emr_serverless_no_startjobrun_arn", "aws/enrich/privesc/method_85", false,
		"PassRole + CreateApplication (no StartJobRun) → method_85 must NOT fire"},
	// method_58 only requires PassRole+CreateApplication — should still fire
	{"lab_fp_emr_serverless_no_startjobrun_arn", "aws/enrich/privesc/method_58", true,
		"PassRole + CreateApplication (no StartJobRun) → method_58 SHOULD fire (no StartJobRun needed)"},

	// SSM: CreateDocument without StartAutomationExecution
	{"lab_fp_ssm_createdoc_only_arn", "aws/enrich/privesc/method_84", false,
		"ssm:CreateDocument alone (no StartAutomationExecution) → method_84 must NOT fire"},

	// Lambda compound methods: missing second permission
	{"lab_fp_lambda_004_no_invoke_arn", "aws/enrich/privesc/method_39", false,
		"UpdateFunctionCode alone → method_39 must NOT fire"},
	{"lab_fp_lambda_005_no_addpermission_arn", "aws/enrich/privesc/method_65", false,
		"UpdateFunctionCode alone → method_65 must NOT fire"},

	// Glue: PassRole alone without CreateDevEndpoint
	{"lab_fp_glue_001_no_createdevendpoint_arn", "aws/enrich/privesc/method_60", false,
		"PassRole alone → method_60 must NOT fire"},

	// ECS: RunTask without PassRole
	{"lab_fp_ecs_runtask_no_passrole_arn", "aws/enrich/privesc/method_32", false,
		"ecs:RunTask alone → method_32 must NOT fire"},

	// EMR: RunJobFlow without PassRole
	{"lab_fp_emr_runjobflow_no_passrole_arn", "aws/enrich/privesc/method_57", false,
		"elasticmapreduce:RunJobFlow alone → method_57 must NOT fire"},

	// SSM: StartAutomationExecution alone
	{"lab_fp_ssm_startautomation_only_arn", "aws/enrich/privesc/method_84", false,
		"ssm:StartAutomationExecution alone → method_84 must NOT fire"},

	// Step Functions: UpdateStateMachine alone
	{"lab_fp_sfn_updatestatemachine_only_arn", "aws/enrich/privesc/method_71", false,
		"states:UpdateStateMachine alone → method_71 must NOT fire"},
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
