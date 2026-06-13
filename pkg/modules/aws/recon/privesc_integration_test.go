//go:build integration

// This is the consolidated AWS-privesc live integration test. It merges the former
// privesc_pathfinding_test.go (the substantive TP/FP matrix, which survives here) with the
// three unique assertions of the former smoke test (suite-level multi-edge count, the
// analysis-query path check, and — superseded — a distinct-target fan-out bound). The smoke
// test's distinct-target <=10 bound is dropped: assertTargetAllowlist is a strictly stronger
// guard. The old aws/recon/privesc fixture the smoke test used is now unused (its Terraform is
// left in place); this suite deploys aws/recon/privesc-pathfinding instead.

package recon

import (
	"context"
	"fmt"
	"os"
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
	"github.com/praetorian-inc/aurelian/test/testutil/privescsynth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// targetKind names the node a method's CAN_PRIVESC edge must terminate at, so a TP case
// asserts the edge lands on the RIGHT node (catching fan-out / mis-target regressions),
// not merely that some edge exists. The concrete ARN is resolved from fixture outputs at
// runtime by targetARN().
type targetKind int

const (
	tgtNone        targetKind = iota // method must emit NO edge for this attacker (FP / no-op)
	tgtSelf                          // self-escalation: attacker -> attacker
	tgtAdminRole                     // trust-backed direct takeover: the :root-trusted admin role
	tgtServiceRole                   // new-passrole: the service-trusted admin role (keyed by svcKey)
	tgtComputeRole                   // existing-compute HAS_ROLE: the compute admin exec role
	tgtPrivUser                      // principal-access: the privileged user
	tgtStub                          // service-wildcard / changeset fail-open: any edge for the method
)

// labCase is one pathfinding.cloud-style scenario.
//   - attackerKey indexes the `attacker_arns` Terraform output map (or `full_attacker_arns`
//     when tier=tierFull).
//   - methodID is the Aurelian enrichment method under test.
//   - want=true → TP: the method must emit ≥1 CAN_PRIVESC edge to `target`.
//   - want=false → FP: the method must emit 0 CAN_PRIVESC edges (by-method, exact).
//   - target identifies the expected TP edge destination (ignored for FP).
//   - svcKey selects the service_admin map entry when target=tgtServiceRole.
//   - tier gates the case on AURELIAN_E2E_FULL.
type labCase struct {
	attackerKey string
	methodID    string
	want        bool
	target      targetKind
	svcKey      string
	tier        tier
	desc        string
}

// knownGaps marks cases that cannot fire on real data. A case here is t.Skip-logged with its
// reason (never silently dropped) so any limitation stays visible. Keyed by attackerKey.
//
// Every case the table covers now fires on live data, so the map is intentionally EMPTY. The
// detection coverage that makes each previously-missing case fire:
//   - iam_create_access_key / ec2_ssm_association / cloudform_create_stackset / bedrock_create_ci:
//     the action allowlist + resource map (action.go + service_action_resource_map.go) let the
//     evaluator emit the required action edges (DeleteAccessKey, CreateAssociation,
//     CreateStackInstances, the bedrock Start/Invoke).
//   - ec2_replace_profile: graph recon enumerates AWS::EC2::Instance, so an `instance`-pattern
//     resource reaches the resource store and ec2:ReplaceIamInstanceProfileAssociation resolves.
//     The live EC2 instance must be present.
//   - iam_pass_role_datapipeline: the three datapipeline actions are allowlisted+mapped, and
//     datapipeline.amazonaws.com is in addServicesToResourceCache's commonServices
//     (analyzer_state.go) so the arn:aws:datapipeline:*:*:* service stub exists in the resource
//     store and GetResourcesByAction resolves → the DATAPIPELINE_* edges are emitted.
//   - cognito_set_pool_roles: the role's Federated cognito trust is surfaced as trusted_federated,
//     and cognito-identity:GetId + GetCredentialsForIdentity are allowlisted (action.go) and
//     mapped (service_action_resource_map.go), so the evaluator emits the
//     COGNITO-IDENTITY_GETID/_GETCREDENTIALSFORIDENTITY edges the guard EXISTS-requires. The
//     fixture grants all three cognito actions + PassRole.
//
// All of this is additive COVERAGE DATA (allowlist / resource-map / service-stub tables) — the
// policy-eval algorithm is untouched.
var knownGaps = map[string]string{}

type tier int

const (
	tierCommon tier = iota
	tierFull
)

const methodPrefix = "aws/enrich/privesc/"

func m(s string) string { return methodPrefix + s }

// labCases is the ground-truth table. Each TP row asserts the edge target identity; each FP
// row asserts 0 edges for the named method (sound: removing the guard flips the assertion).
var labCases = []labCase{
	// ===== IAM self-escalation (target = self) =====
	{"iam_create_policy_version", m("iam_create_policy_version"), true, tgtSelf, "", tierCommon, "CreatePolicyVersion on a customer-managed policy attached to self"},
	{"iam_set_default_policy_version", m("iam_set_default_policy_version"), true, tgtSelf, "", tierCommon, "SetDefaultPolicyVersion on a self-attached customer policy"},
	{"iam_put_user_policy", m("iam_put_user_policy"), true, tgtSelf, "", tierCommon, "PutUserPolicy on self"},
	{"iam_attach_user_policy", m("iam_attach_user_policy"), true, tgtSelf, "", tierCommon, "AttachUserPolicy on self"},
	{"iam_put_group_policy", m("iam_put_group_policy"), true, tgtSelf, "", tierCommon, "PutGroupPolicy on a group the attacker is in"},
	{"iam_attach_group_policy", m("iam_attach_group_policy"), true, tgtSelf, "", tierCommon, "AttachGroupPolicy on a group the attacker is in"},
	{"iam_add_user_to_group", m("iam_add_user_to_group"), true, tgtSelf, "", tierCommon, "AddUserToGroup into the admin group (not already a member)"},
	{"ssm_createdoc_startauto", m("ssm_createdocument_startautomation"), true, tgtSelf, "", tierCommon, "CreateDocument+StartAutomationExecution self-escalation"},

	// ===== IAM principal-access (target = privileged user) =====
	{"iam_create_access_key", m("iam_create_access_key"), true, tgtPrivUser, "", tierCommon, "CreateAccessKey+DeleteAccessKey on the privileged user"},
	{"iam_create_login_profile", m("iam_create_login_profile"), true, tgtPrivUser, "", tierCommon, "CreateLoginProfile+UpdateLoginProfile on the privileged user"},
	{"iam_update_login_profile", m("iam_update_login_profile"), true, tgtPrivUser, "", tierCommon, "UpdateLoginProfile on the privileged user"},

	// ===== IAM trust-backed direct takeover (target = :root-trusted admin role) =====
	{"iam_put_role_policy", m("iam_put_role_policy"), true, tgtAdminRole, "", tierCommon, "PutRolePolicy + assumable (:root trust) admin role"},
	{"iam_attach_role_policy", m("iam_attach_role_policy"), true, tgtAdminRole, "", tierCommon, "AttachRolePolicy + assumable admin role"},
	{"iam_update_assume_role_policy", m("iam_update_assume_role_policy"), true, tgtAdminRole, "", tierCommon, "UpdateAssumeRolePolicy on the admin role"},
	{"sts_assume_role", m("sts_assume_role"), true, tgtAdminRole, "", tierCommon, "AssumeRole + :root trust → CAN_ASSUME to admin role"},
	{"passrole_modify_policy", m("passrole_modify_policy"), true, tgtAdminRole, "", tierCommon, "PassRole + AttachRolePolicy on the admin role"},
	{"update_assume_role_passrole_service", m("update_assume_role_passrole_service"), true, tgtAdminRole, "", tierCommon, "UpdateAssumeRolePolicy + PassRole on the admin role"},

	// ===== New-passrole + create compute (target = service-trusted admin role) =====
	{"iam_pass_role_ec2", m("iam_pass_role_ec2"), true, tgtServiceRole, "ec2", tierCommon, "PassRole(ec2-trusting admin) + RunInstances"},
	{"iam_pass_role_lambda", m("iam_pass_role_lambda"), true, tgtServiceRole, "lambda", tierCommon, "PassRole(lambda-trusting admin) + CreateFunction"},
	{"iam_pass_role_cloudform", m("iam_pass_role_cloudformation"), true, tgtServiceRole, "cloudform", tierCommon, "PassRole(cfn-trusting admin) + CreateStack"},
	{"cloudform_create_stackset", m("cloudformation_create_stackset"), true, tgtServiceRole, "cloudform", tierCommon, "PassRole(cfn-trusting admin) + CreateStackSet+CreateStackInstances"},
	{"iam_pass_role_datapipeline", m("iam_pass_role_datapipeline"), true, tgtServiceRole, "datapipeline", tierCommon, "PassRole(datapipeline-trusting admin) + CreatePipeline+PutPipelineDefinition+ActivatePipeline"},
	{"iam_pass_role_glue", m("iam_pass_role_glue"), true, tgtServiceRole, "glue", tierCommon, "PassRole(glue-trusting admin) + CreateJob"},
	{"iam_pass_role_sagemaker", m("iam_pass_role_sagemaker"), true, tgtServiceRole, "sagemaker", tierCommon, "PassRole(sagemaker-trusting admin) + CreateNotebookInstance"},
	{"ec2_request_spot", m("ec2_request_spot_instances"), true, tgtServiceRole, "ec2", tierCommon, "PassRole(ec2) + RequestSpotInstances"},
	{"ec2_replace_profile", m("ec2_replace_instance_profile"), true, tgtServiceRole, "ec2", tierCommon, "PassRole(ec2) + ReplaceIamInstanceProfileAssociation"},
	{"ec2_launch_template_ver", m("ec2_launch_template_version"), true, tgtServiceRole, "ec2", tierCommon, "PassRole(ec2) + CreateLaunchTemplateVersion+ModifyLaunchTemplate"},
	{"autoscaling_launch_tpl", m("autoscaling_launch_template"), true, tgtServiceRole, "ec2", tierCommon, "PassRole(ec2) + CreateLaunchTemplate+CreateAutoScalingGroup"},
	{"apprunner_create_service", m("apprunner_create_service"), true, tgtServiceRole, "apprunner", tierCommon, "PassRole(apprunner) + CreateService"},
	{"codebuild_create_project", m("codebuild_create_project"), true, tgtServiceRole, "codebuild", tierCommon, "PassRole(codebuild) + CreateProject"},
	{"codebuild_update_project", m("codebuild_update_project"), true, tgtServiceRole, "codebuild", tierCommon, "PassRole(codebuild) + UpdateProject"},
	// cognito_set_pool_roles: the role's Federated cognito trust is surfaced as trusted_federated
	// and GetId+GetCredentialsForIdentity are allowlisted, so the guard's two EXISTS clauses are
	// satisfied by real evaluator-emitted edges.
	{"cognito_set_pool_roles", m("cognito_set_identity_pool_roles"), true, tgtServiceRole, "cognito", tierCommon, "PassRole(cognito) + SetIdentityPoolRoles + GetId + GetCredentialsForIdentity"},
	{"ecs_create_service", m("ecs_create_service"), true, tgtServiceRole, "ecstasks", tierCommon, "PassRole(ecs-tasks) + CreateService"},
	{"ecs_passrole_runtask", m("ecs_passrole_runtask"), true, tgtServiceRole, "ecstasks", tierCommon, "PassRole(ecs-tasks) + RunTask"},
	{"ecs_start_task", m("ecs_start_task"), true, tgtServiceRole, "ecstasks", tierCommon, "PassRole(ecs-tasks) + StartTask"},
	{"glue_create_dev_endpoint", m("glue_create_dev_endpoint"), true, tgtServiceRole, "glue", tierCommon, "PassRole(glue) + CreateDevEndpoint"},
	{"glue_create_session", m("glue_create_session"), true, tgtServiceRole, "glue", tierCommon, "PassRole(glue) + CreateSession"},
	{"glue_createjob_trigger", m("glue_createjob_createtrigger"), true, tgtServiceRole, "glue", tierCommon, "PassRole(glue) + CreateJob+CreateTrigger"},
	{"glue_createjob_startjobrun", m("glue_createjob_startjobrun"), true, tgtServiceRole, "glue", tierCommon, "PassRole(glue) + CreateJob+StartJobRun"},
	{"glue_session_runstatement", m("glue_createsession_runstatement"), true, tgtServiceRole, "glue", tierCommon, "PassRole(glue) + CreateSession+RunStatement"},
	{"scheduler_create_schedule", m("scheduler_create_schedule"), true, tgtServiceRole, "scheduler", tierCommon, "PassRole(scheduler) + CreateSchedule"},
	{"ssm_start_automation", m("ssm_start_automation"), true, tgtServiceRole, "ssm", tierCommon, "PassRole(ssm) + StartAutomationExecution"},
	{"stepfunctions_create", m("stepfunctions_create"), true, tgtServiceRole, "states", tierCommon, "PassRole(states) + CreateStateMachine"},
	{"stepfunctions_create_start", m("stepfunctions_create_startexecution"), true, tgtServiceRole, "states", tierCommon, "PassRole(states) + CreateStateMachine+StartExecution"},
	{"lambda_passrole_addperm", m("lambda_passrole_createfunction_addpermission"), true, tgtServiceRole, "lambda", tierCommon, "PassRole(lambda) + CreateFunction+AddPermission"},
	{"sagemaker_processing_job", m("sagemaker_processing_job"), true, tgtServiceRole, "sagemaker", tierCommon, "PassRole(sagemaker) + CreateProcessingJob"},
	{"sagemaker_training_job", m("sagemaker_training_job"), true, tgtServiceRole, "sagemaker", tierCommon, "PassRole(sagemaker) + CreateTrainingJob"},
	{"bedrock_create_ci", m("bedrock_create_code_interpreter"), true, tgtServiceRole, "bedrock", tierCommon, "PassRole(bedrock-agentcore) + CreateCodeInterpreter+StartSession"},
	{"amplify_create_app", m("amplify_create_app"), true, tgtServiceRole, "amplify", tierCommon, "PassRole(amplify) + CreateApp"},
	{"batch_passrole", m("batch_passrole"), true, tgtServiceRole, "ecstasks", tierCommon, "PassRole(ecs-tasks) + RegisterJobDefinition+SubmitJob"},

	// ===== Existing-compute via HAS_ROLE (target = compute exec role) =====
	{"lambda_update_code", m("lambda_update_function_code"), true, tgtComputeRole, "", tierCommon, "UpdateFunctionCode+InvokeFunction on the admin-role Lambda"},
	{"lambda_updatecode_invoke", m("lambda_updatecode_invoke"), true, tgtComputeRole, "", tierCommon, "UpdateFunctionCode+InvokeFunction compound on the Lambda"},
	{"lambda_add_permission", m("lambda_add_permission"), true, tgtComputeRole, "", tierCommon, "UpdateFunctionCode+AddPermission on the Lambda"},
	{"lambda_create_esm", m("lambda_create_event_source_mapping"), true, tgtComputeRole, "", tierCommon, "UpdateFunctionCode+CreateEventSourceMapping on the Lambda"},
	{"ec2_modify_attribute", m("ec2_modify_instance_attribute"), true, tgtComputeRole, "", tierCommon, "ModifyInstanceAttribute+Stop+Start on the admin-role EC2 instance"},
	{"ec2_instance_connect", m("ec2_instance_connect"), true, tgtComputeRole, "", tierCommon, "SendSSHPublicKey to the admin-role EC2 instance"},
	{"ec2_ssm_association", m("ec2_ssm_association"), true, tgtComputeRole, "", tierCommon, "CreateAssociation on the ssm-enabled admin EC2 instance"},
	{"ssm_send_command", m("ssm_send_command"), true, tgtComputeRole, "", tierCommon, "SendCommand to the ssm-enabled admin EC2 instance"},
	{"ssm_start_session", m("ssm_start_session"), true, tgtComputeRole, "", tierCommon, "StartSession on the ssm-enabled admin EC2 instance"},
	{"cloudform_update_stack", m("cloudformation_update_stack"), true, tgtComputeRole, "", tierCommon, "UpdateStack on a stack running the admin role (REAL fixture CFN stack, RoleARN→compute_admin)"},
	{"cloudform_update_stackset", m("cloudformation_update_stackset"), true, tgtComputeRole, "", tierCommon, "UpdateStackSet on a stackset running the admin role (REAL fixture CFN stackset, AdministrationRoleARN→compute_admin)"},
	{"codebuild_start_build", m("codebuild_start_build"), true, tgtComputeRole, "", tierCommon, "StartBuild on a project running the admin role (REAL fixture CodeBuild project, ServiceRole→compute_admin)"},
	{"codedeploy_create_deploy", m("codedeploy_create_deployment"), true, tgtComputeRole, "", tierCommon, "CreateDeployment onto the admin-role EC2 instance"},
	{"apprunner_update_service", m("apprunner_update_service"), true, tgtComputeRole, "", tierCommon, "UpdateService on a service running the admin role (synthetic — App Runner not provisioned)"},
	{"ecs_execute_command", m("ecs_execute_command"), true, tgtComputeRole, "", tierCommon, "ExecuteCommand on a task running the admin role (REAL fixture ECS task definition, TaskRoleArn→compute_admin)"},
	{"stepfunctions_update", m("stepfunctions_update"), true, tgtComputeRole, "", tierCommon, "UpdateStateMachine+StartExecution on an admin-role state machine (REAL fixture SFN state machine, RoleArn→compute_admin)"},
	{"glue_update_dev_endpoint", m("glue_update_dev_endpoint"), true, tgtComputeRole, "", tierCommon, "UpdateDevEndpoint on an admin-role dev endpoint (synthetic — Glue DevEndpoint not provisioned)"},
	{"glue_update_job", m("glue_update_job"), true, tgtComputeRole, "", tierCommon, "UpdateJob on an admin-role glue job (REAL fixture Glue job, Role→compute_admin ARN)"},
	{"glue_updatejob_startjobrun", m("glue_updatejob_startjobrun"), true, tgtComputeRole, "", tierCommon, "UpdateJob+StartJobRun on an admin-role glue job (REAL fixture Glue job)"},
	{"glue_updatejob_trigger", m("glue_updatejob_createtrigger"), true, tgtComputeRole, "", tierCommon, "UpdateJob+CreateTrigger on an admin-role glue job (REAL fixture Glue job)"},
	{"sagemaker_lifecycle", m("sagemaker_lifecycle_config"), true, tgtComputeRole, "", tierCommon, "UpdateNotebookInstanceLifecycleConfig on an admin-role notebook (synthetic — SageMaker notebook not provisioned)"},
	{"sagemaker_presigned", m("sagemaker_presigned_url"), true, tgtComputeRole, "", tierCommon, "CreatePresignedNotebookInstanceUrl on an admin-role notebook (synthetic — SageMaker notebook not provisioned)"},

	// ===== Existing-resource takeover via HAS_ROLE (target = the backing resource's privileged
	// role, reached via (Resource)-[:HAS_ROLE]->(role), not a service-wildcard stub) =====
	// The action edges (BATCH_SUBMITJOB / BEDROCK-AGENTCORE_INVOKESESSION /
	// CLOUDFORMATION_{CREATE,EXECUTE}CHANGESET) are genuinely evaluator-emitted on live data
	// (allowlisted + mapped to the service stub). Batch JobDefinition AND CFN Stack are REAL fixture
	// resources (collected by recon, seeded via NodeFromAWSResource → real HAS_ROLE), so
	// batch_submit_job and cloudform_changeset run on the REAL path (verified by real_path/batch_jobdef
	// + the CFN real_path subtests). AgentCore CodeInterpreter has NO Terraform provider resource
	// (preview service), so bedrock_invoke keeps a SYNTHETIC HAS_ROLE source pointing at the
	// correctly-trusted bedrock-agentcore svcadmin role; its collector is unit-tested, live-path
	// verification deferred.
	{"batch_submit_job", m("batch_submit_job"), true, tgtServiceRole, "ecstasks", tierCommon, "SubmitJob on a REAL fixture Batch JobDefinition whose jobRoleArn is the privileged ecs-tasks-trusting svcadmin role"},
	{"bedrock_invoke", m("bedrock_access_code_interpreter"), true, tgtServiceRole, "bedrock", tierCommon, "InvokeSession on a synthetic AgentCore CodeInterpreter whose ExecutionRoleArn is the privileged bedrock-agentcore svcadmin role (AgentCore not provisionable via TF)"},
	{"cloudform_changeset", m("cloudformation_changeset"), true, tgtComputeRole, "", tierCommon, "CreateChangeSet+ExecuteChangeSet against a REAL fixture CFN Stack whose RoleARN is the privileged compute admin role"},

	// ===== Intentional no-op (target = none) =====
	{"iam_create_slr", m("iam_create_service_linked_role"), false, tgtNone, "", tierCommon, "CreateServiceLinkedRole emits no CAN_PRIVESC (RETURN 0)"},
	{"codestar_create", m("codestar_create_project"), false, tgtNone, "", tierCommon, "CreateProject points at a service stub (not a Principal) on the live fixture → no edge"},

	// =========================================================================
	// FALSE POSITIVES — the named method must NOT fire (0 edges by-method).
	// =========================================================================

	// cat-1 missing-permission
	{"fp_passrole_only", m("iam_pass_role_lambda"), false, tgtNone, "", tierCommon, "PassRole alone (no CreateFunction)"},
	{"fp_passrole_only", m("iam_pass_role_ec2"), false, tgtNone, "", tierCommon, "PassRole alone (no RunInstances)"},
	{"fp_lambda_create_only", m("iam_pass_role_lambda"), false, tgtNone, "", tierCommon, "CreateFunction alone (no PassRole)"},
	{"fp_lambda_invoke_only", m("lambda_updatecode_invoke"), false, tgtNone, "", tierCommon, "InvokeFunction alone (no UpdateFunctionCode)"},
	{"fp_lambda_no_trigger", m("lambda_updatecode_invoke"), false, tgtNone, "", tierCommon, "UpdateFunctionCode alone (no trigger primitive)"},
	{"fp_ec2_run_only", m("iam_pass_role_ec2"), false, tgtNone, "", tierCommon, "RunInstances alone (no PassRole)"},
	{"fp_cfn_create_only", m("iam_pass_role_cloudformation"), false, tgtNone, "", tierCommon, "CreateStack alone (no PassRole)"},
	{"fp_glue_createjob_only", m("glue_createjob_startjobrun"), false, tgtNone, "", tierCommon, "CreateJob alone (no PassRole/StartJobRun)"},
	{"fp_sfn_no_start", m("stepfunctions_create_startexecution"), false, tgtNone, "", tierCommon, "PassRole+CreateStateMachine (no StartExecution)"},
	{"fp_sfn_no_start", m("stepfunctions_create"), true, tgtServiceRole, "states", tierCommon, "PassRole+CreateStateMachine → stepfunctions_create SHOULD still fire"},
	{"fp_ecs_create_only", m("ecs_create_service"), false, tgtNone, "", tierCommon, "CreateService alone (no PassRole)"},
	{"fp_ssm_createdoc_only", m("ssm_createdocument_startautomation"), false, tgtNone, "", tierCommon, "CreateDocument alone (no StartAutomationExecution)"},
	{"fp_changeset_create_only", m("cloudformation_changeset"), false, tgtNone, "", tierCommon, "CreateChangeSet alone (no ExecuteChangeSet)"},
	// cat-1 (legacy-matrix parity): preserve the FP coverage the old suite had for these methods.
	{"fp_passrole_only", m("ec2_request_spot_instances"), false, tgtNone, "", tierCommon, "PassRole alone (no RequestSpotInstances)"},
	{"fp_passrole_only", m("glue_create_dev_endpoint"), false, tgtNone, "", tierCommon, "PassRole alone (no CreateDevEndpoint)"},
	{"fp_lambda_no_trigger", m("lambda_add_permission"), false, tgtNone, "", tierCommon, "UpdateFunctionCode alone (no AddPermission)"},
	{"fp_ecs_runtask_no_passrole", m("ecs_passrole_runtask"), false, tgtNone, "", tierCommon, "RunTask alone (no PassRole)"},
	{"fp_sfn_updatesm_only", m("stepfunctions_update"), false, tgtNone, "", tierCommon, "UpdateStateMachine alone (no StartExecution)"},

	// cat-2 trust-policy-mismatch (PassRole scoped to the wrong-service decoy role)
	{"fp_passrole_wrong_service", m("iam_pass_role_lambda"), false, tgtNone, "", tierCommon, "PassRole scoped to a non-lambda-trusting (sqs) role → iam_pass_role_lambda must NOT fire"},

	// cat-4 target-not-privileged (PassRole/CreateAccessKey scoped to a non-privileged target)
	{"fp_passrole_nonpriv_target", m("iam_pass_role_lambda"), false, tgtNone, "", tierCommon, "PassRole scoped to a lambda-trusting but NON-privileged role → must NOT fire"},
	{"fp_accesskey_nonpriv", m("iam_create_access_key"), false, tgtNone, "", tierCommon, "CreateAccessKey+DeleteAccessKey but the only reachable user is non-privileged"},

	// ===== Full-tier (skipped unless AURELIAN_E2E_FULL=1) =====
	{"emr_run_job_flow", m("emr_run_job_flow"), true, tgtServiceRole, "emr", tierFull, "PassRole(emr) + RunJobFlow"},
	{"emr_serverless", m("emr_serverless"), true, tgtServiceRole, "emrserverless", tierFull, "PassRole(emr-serverless) + CreateApplication"},
	{"emr_serverless_startjobrun", m("emr_serverless_startjobrun"), true, tgtServiceRole, "emrserverless", tierFull, "PassRole(emr-serverless) + CreateApplication+StartJobRun"},
	{"gamelift_create_fleet", m("gamelift_create_fleet"), true, tgtServiceRole, "gamelift", tierFull, "PassRole(gamelift) + CreateFleet"},
	{"gamelift_build_fleet", m("gamelift_createbuild_createfleet"), true, tgtServiceRole, "gamelift", tierFull, "PassRole(gamelift) + CreateBuild+CreateFleet"},
	{"imagebuilder_pipeline", m("imagebuilder_create_pipeline"), true, tgtServiceRole, "imagebuilder", tierFull, "PassRole(ec2) + CreateInfrastructureConfiguration"},
	{"imagebuilder_createimage", m("imagebuilder_createimage"), true, tgtServiceRole, "imagebuilder", tierFull, "PassRole(ec2) + CreateInfrastructureConfiguration+CreateImage"},
	{"braket_create_job", m("braket_create_job"), true, tgtServiceRole, "braket", tierFull, "PassRole(braket) + CreateJob"},
	{"omics_create_workflow", m("omics_create_workflow"), true, tgtServiceRole, "omics", tierFull, "PassRole(omics) + CreateWorkflow"},
	{"omics_startrun", m("omics_startrun"), true, tgtServiceRole, "omics", tierFull, "PassRole(omics) + CreateWorkflow+StartRun"},
	{"kinesisanalytics", m("kinesis_analytics"), true, tgtServiceRole, "kinesisanalytics", tierFull, "PassRole(kinesisanalytics) + CreateApplication"},
	{"kinesisanalytics_startapp", m("kinesisanalytics_startapplication"), true, tgtServiceRole, "kinesisanalytics", tierFull, "PassRole(kinesisanalytics) + CreateApplication+StartApplication"},
	{"fp_emr_runjobflow_no_passrole", m("emr_run_job_flow"), false, tgtNone, "", tierFull, "RunJobFlow alone (no PassRole)"},
	{"fp_emrserverless_no_start", m("emr_serverless_startjobrun"), false, tgtNone, "", tierFull, "PassRole+CreateApplication (no StartJobRun)"},
}

// peMethodLiteral extracts the human-readable method string a privesc query stamps onto its
// CAN_PRIVESC edge (e.g. "iam:PassRole + lambda:CreateFunction"). FP assertions match this
// exact value (read from the loaded Cypher, not a hardcoded map) so a renamed literal fails
// loud rather than turning the FP check vacuous. CAN_PRIVESC is multi-edge: `method` lives
// in the MERGE relationship pattern, so we match the `{method: '<M>'}` literal.
var peMethodRe = regexp.MustCompile(`CAN_PRIVESC\s*\{method:\s*'([^']*)'\}`)

func peMethodLiteral(methodID string) (string, bool) {
	q, ok := queries.GetQuery(methodID)
	if !ok {
		return "", false
	}
	mm := peMethodRe.FindStringSubmatch(q.Cypher)
	if len(mm) != 2 {
		return "", false
	}
	return mm[1], true
}

// fixtureFacts holds the resolved fixture ARNs the case table needs.
type fixtureFacts struct {
	attackerARNs     map[string]string // attackerKey -> ARN (common + full merged)
	serviceAdminARNs map[string]string // svcKey -> ARN (common + full merged)
	adminTargetARN   string
	computeAdminARN  string
	privUserARN      string
	prefix           string   // this fixture's "aur-pf-<id>" name prefix (scopes the no-fan-out guard)
	accountID        string   // the fixture's AWS account id (distinguishes real vs synthetic 000000000000)
	decoyARNs        []string // FP decoy role ARNs (legitimately modifiable role targets)
}

// account returns the fixture's real AWS account id (e.g. "196766918487"), used to assert that a
// collected :Resource node carries a REAL-account ARN rather than the synthetic 000000000000 one.
func (f fixtureFacts) account() string { return f.accountID }

// targetARN resolves the expected TP edge destination for a case.
func (f fixtureFacts) targetARN(tc labCase) string {
	switch tc.target {
	case tgtSelf:
		return f.attackerARNs[tc.attackerKey]
	case tgtAdminRole:
		return f.adminTargetARN
	case tgtServiceRole:
		return f.serviceAdminARNs[tc.svcKey]
	case tgtComputeRole:
		return f.computeAdminARN
	case tgtPrivUser:
		return f.privUserARN
	default:
		return ""
	}
}

// TestPrivescPathfindingCloudE2E is the full-stack TP+FP integration test: it deploys the
// rebuilt fixture, runs graph recon, seeds RICH GAAD nodes plus synthetic compute Resource
// nodes into Neo4j, runs EnrichAWS, and asserts per-method TP (edge to the CORRECT target)
// and FP (0 edges by-method) plus a global target-allowlist / no-fan-out guard.
//
// Run: go test -tags integration -run TestPrivescPathfindingCloudE2E ./pkg/modules/aws/recon/...
// Full tier (expensive backing compute + cases): AURELIAN_E2E_FULL=1.
func TestPrivescPathfindingCloudE2E(t *testing.T) {
	ctx := context.Background()
	fullTier := os.Getenv("AURELIAN_E2E_FULL") == "1"

	// --- Step 1: Deploy fixture ---
	// terraform-exec inherits this process's env, so TF_VAR_enable_full reaches the apply.
	if fullTier {
		t.Setenv("TF_VAR_enable_full", "true")
	}
	fixture := testutil.NewAWSFixture(t, "aws/recon/privesc-pathfinding")
	fixture.Setup()

	allARNs := fixture.OutputList("all_arns")
	fixtureARNs := make(map[string]bool, len(allARNs))
	for _, arn := range allARNs {
		fixtureARNs[arn] = true
	}

	facts := fixtureFacts{
		attackerARNs:     fixture.OutputMap("attacker_arns"),
		serviceAdminARNs: fixture.OutputMap("service_admin_arns"),
		adminTargetARN:   fixture.Output("admin_target_arn"),
		computeAdminARN:  fixture.Output("compute_admin_arn"),
		privUserARN:      fixture.Output("priv_user_arn"),
		prefix:           fixture.Output("prefix"),
		accountID:        fixture.Output("account_id"),
		// Admin/decoy roles no per-case TP points at but a broad-Resource attacker (e.g.
		// iam:UpdateAssumeRolePolicy on "*") can legitimately reach, so they belong in the
		// no-fan-out allowlist. Includes the FP-category decoys and the Federated-trust cognito
		// role (a frozen-query known gap, not a passrole TP target — see the cognito labCase).
		decoyARNs: []string{
			fixture.Output("trust_mismatch_target_arn"),
			fixture.Output("wrong_service_target_arn"),
			fixture.Output("nonpriv_lambda_target_arn"),
			fixture.Output("cognito_admin_arn"),
		},
	}
	if fullTier {
		for k, v := range fixture.OutputMap("full_attacker_arns") {
			facts.attackerARNs[k] = v
		}
		for k, v := range fixture.OutputMap("full_service_admin_arns") {
			facts.serviceAdminARNs[k] = v
		}
	}
	t.Logf("Loaded %d attacker ARNs, %d service-admin ARNs (full=%v)",
		len(facts.attackerARNs), len(facts.serviceAdminARNs), fullTier)

	// The synthetic compute Resource ARNs (for HAS_ROLE methods whose backing service is NOT
	// provisioned in the fixture — App Runner, Glue DevEndpoint, SageMaker notebook, Bedrock-CI,
	// plus the Lambda/EC2 same-node anchors) run a privileged role and must be treated as
	// fixture-owned. The kept Bedrock-CI re-point needs the bedrock-agentcore-trusting svcadmin role.
	syntheticResources := privescsynth.SyntheticComputeResources(
		facts.computeAdminARN,
		fixture.Output("ec2_instance_arn"),
		facts.serviceAdminARNs["bedrock"],
	)
	for _, r := range syntheticResources {
		fixtureARNs[r.ARN] = true
	}

	// --- Step 2: Run graph recon ---
	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "graph")
	require.True(t, ok, "graph module should be registered")

	cfg := plugin.Config{Args: map[string]any{"regions": []string{"us-east-2"}}, Context: ctx}
	p1 := pipeline.From(cfg)
	p2 := pipeline.New[model.AurelianModel]()
	pipeline.Pipe(p1, mod.Run, p2)

	var iamResources []output.AWSIAMResource
	var iamRels []output.AWSIAMRelationship
	var collectedResources []output.AWSResource // real non-IAM resources (CFN/ECS/SFN/Glue/CodeBuild/Batch/…)
	for m := range p2.Range() {
		switch v := m.(type) {
		case output.AWSIAMResource:
			iamResources = append(iamResources, v)
		case output.AWSIAMRelationship:
			iamRels = append(iamRels, v)
		case output.AWSResource:
			// The graph module ALSO emits the collected service resources
			// (resourcesWithPolicies). These are the REAL backing resources the
			// existing-compute HAS_ROLE methods re-point at; capture them so the REAL
			// collection → resource_service_role → HAS_ROLE path is exercised end-to-end
			// (previously dropped, so the synthetic stand-ins were the only HAS_ROLE source).
			collectedResources = append(collectedResources, v)
		}
	}
	require.NoError(t, p2.Wait())
	require.NotEmpty(t, iamRels, "recon should produce IAM relationships")

	// Keep only this fixture's collected resources: every fixture backing-resource runs a
	// fixture role whose ARN carries the run prefix (aur-pf-<id>), and the role ARN appears as
	// a quoted value inside the flattened properties JSON (or a top-level Role prop). Matching
	// the prefix bounds the graph against the shared bfr account's other live fixtures.
	var fixtureCollected []output.AWSResource
	for _, r := range collectedResources {
		if resourceReferencesPrefix(r, facts.prefix) {
			fixtureCollected = append(fixtureCollected, r)
		}
	}
	t.Logf("Collected resources: %d total, %d fixture-owned (prefix %s)",
		len(collectedResources), len(fixtureCollected), facts.prefix)

	// Capture a replay snapshot when explicitly requested (no-op on normal/CI runs so the tree
	// stays clean). It serializes the TYPED GAAD structs recovered from each fixture IAM entity's
	// OriginalData plus the fixture relationships, collected resources, and the ARNs the kept
	// synthetics bind to, so TestPrivescSnapshotReplay can rebuild this graph with no AWS access.
	if os.Getenv("AURELIAN_CAPTURE_PRIVESC_SNAPSHOT") == "1" {
		var fixtureIAM []output.AWSIAMResource
		for _, r := range iamResources {
			if r.ARN == "" || fixtureARNs[r.ARN] {
				fixtureIAM = append(fixtureIAM, r)
			}
		}
		var fixtureRels []output.AWSIAMRelationship
		for _, r := range iamRels {
			if fixtureARNs[r.Principal.ARN] || fixtureARNs[r.Resource.ARN] {
				fixtureRels = append(fixtureRels, r)
			}
		}
		inputs := privescsynth.SyntheticInputs{
			ComputeAdminARN:  facts.computeAdminARN,
			EC2InstanceARN:   fixture.Output("ec2_instance_arn"),
			BedrockExecRole:  facts.serviceAdminARNs["bedrock"],
			AdminTargetARN:   facts.adminTargetARN,
			PrivUserARN:      facts.privUserARN,
			Prefix:           facts.prefix,
			AccountID:        facts.accountID,
			ServiceAdminARNs: facts.serviceAdminARNs,
			AttackerARNs:     facts.attackerARNs,
			DecoyARNs:        facts.decoyARNs,
		}
		require.NoError(t, privescsynth.CaptureToFile(privescsynth.SnapshotPath, fixtureIAM, fixtureRels, fixtureCollected, inputs))
		t.Logf("captured privesc recon snapshot to %s", privescsynth.SnapshotPath)
	}

	// --- Step 3: Write to Neo4j ---
	boltURL, cleanup, err := testutil.StartNeo4jContainer(ctx)
	require.NoError(t, err)
	t.Cleanup(cleanup)

	dbCfg := graph.NewConfig(boltURL, "", "")
	db, err := adapters.NewNeo4jAdapter(dbCfg)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	// 3a. Seed RICH GAAD nodes for every fixture IAM entity. Unlike the relationship-only
	// nodes (which carry just {Arn}), these carry trusted_services / AssumeRolePolicyDocument
	// / InstanceProfileList / AttachedManagedPolicies / GroupList — the inputs the trust,
	// admin, instance-profile and self-loop guards read. Without this NO trust/HAS_ROLE/
	// self-loop method can fire on the live fixture (without it, no trust/HAS_ROLE/self-loop fires).
	seen := map[string]bool{}
	var nodes []*graph.Node
	addNode := func(n *graph.Node) {
		if n == nil || len(n.UniqueKey) == 0 {
			return
		}
		key := fmt.Sprintf("%v", n.Properties[n.UniqueKey[0]])
		if key == "" || seen[key] {
			return
		}
		seen[key] = true
		nodes = append(nodes, n)
	}
	for _, r := range iamResources {
		if r.ARN != "" && !fixtureARNs[r.ARN] {
			continue // only seed fixture-owned entities to keep the graph bounded
		}
		addNode(awstransformers.NodeFromAWSIAMResource(r))
	}

	// 3b-real. Seed the REAL collected backing resources (CFN stack/stackset, ECS task
	// def, SFN state machine, Glue job, CodeBuild project, Batch job def) through the PRODUCTION
	// transformer NodeFromAWSResource — exactly as `recon graph` seeds them. resource_service_role
	// then builds (realResource)-[:HAS_ROLE]->(privileged role) by substring-matching the role ARN
	// inside the flattened properties JSON. This is the REAL collection → HAS_ROLE path; the
	// provisioned types no longer rely on a synthetic stand-in.
	for _, r := range fixtureCollected {
		addNode(awstransformers.NodeFromAWSResource(r))
	}

	// 3b-synthetic. Seed synthetic compute Resource nodes for the HAS_ROLE methods whose backing
	// service is NOT provisioned in the fixture (cost/complexity — see syntheticComputeResources):
	// App Runner, SageMaker notebook, Glue dev endpoint, Bedrock AgentCore code interpreter; plus
	// real Lambda + EC2 (still seeded here for the same-node-binding action edges in 3d). Their
	// collectors are unit-tested; live-path verification is deferred for those types.
	for _, sr := range syntheticResources {
		addNode(sr.Node())
	}

	// 3c. Seed the fixture's permission relationships (the action edges).
	var rels []*graph.Relationship
	for _, r := range iamRels {
		if !fixtureARNs[r.Principal.ARN] && !fixtureARNs[r.Resource.ARN] {
			continue
		}
		if rel := awstransformers.RelationshipFromAWSIAMRelationship(r); rel != nil {
			rels = append(rels, rel)
			addNode(rel.StartNode)
			addNode(rel.EndNode)
		}
	}
	require.NotEmpty(t, rels, "fixture principals should have IAM relationships")

	// 3d. Seed action edges from the same-node-binding HAS_ROLE attackers to the Resource node
	// carrying HAS_ROLE. The lambda_*/apprunner_update_service/stepfunctions_update guards MATCH the
	// action edge and the (Resource)-[:HAS_ROLE]->(role) edge on the SAME node, but real recon
	// resolves a '*' action to the AWS::Service stub, not to the specific Resource. On a real account
	// the action resolves to the real resource (which is also the HAS_ROLE source), so these edges
	// faithfully model production recon. For stepfunctions_update the real SFN StateMachine is
	// collected, so its action edges attach to the REAL node (realResourceARNs); lambda /
	// apprunner stay on their synthetic stand-ins.
	// (Decoupled HAS_ROLE methods — ssm/glue/codebuild/ec2_modify/cfn — need no such edge: they
	// EXISTS the action against any target and reach the resource via a separate HAS_ROLE MATCH.)
	realResourceARNs := map[string]string{}
	for _, r := range fixtureCollected {
		realResourceARNs[r.ResourceType] = r.ARN
	}
	rels = append(rels, privescsynth.SyntheticActionEdges(facts.attackerARNs, syntheticResources, realResourceARNs)...)

	// 3e. Same-node-binding relocation for lambda_passrole_createfunction_addpermission (same
	// soundness class as 3d, not an evaluator-emission gap). lambda:CreateFunction AND
	// lambda:AddPermission are BOTH allowlisted (action.go) and mapped, so the frozen evaluator
	// DOES emit both edges — but the resource map binds createfunction to the AWS::Service stub
	// and addpermission to the function node, while the guard MATCHes both on the SAME svc node.
	// Seeding both onto one shared stub faithfully relocates the two genuinely-emitted edges onto
	// a single node (exactly the 3d compromise), keyed strictly to the TP attacker — no FP attacker
	// is seeded. (Methods whose guard requires an action the evaluator NEVER emits are NOT seeded
	// here — they are skip-logged known gaps; see knownGaps.)
	stub := privescsynth.SameNodeStubNode()
	addNode(stub)
	rels = append(rels, privescsynth.SameNodeStubEdges(facts.attackerARNs, stub)...)

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
	require.NoError(t, queries.EnrichAWS(ctx, db))
	t.Logf("Graph seeded: %d nodes, %d edges", len(nodes), len(rels))

	// --- Step 5: Per-case assertions ---
	for _, tc := range labCases {
		tc := tc
		name := fmt.Sprintf("%s/%s/%s",
			map[bool]string{true: "TP", false: "FP"}[tc.want],
			tc.attackerKey, tc.methodID[strings.LastIndex(tc.methodID, "/")+1:])
		t.Run(name, func(t *testing.T) {
			if reason, gap := knownGaps[tc.attackerKey]; gap {
				t.Skipf("known gap (frozen query, not fixed this PR): %s — %s", tc.desc, reason)
			}
			if tc.tier == tierFull && !fullTier {
				t.Skipf("tier=full, AURELIAN_E2E_FULL not set — case authored but backing resources not provisioned: %s", tc.desc)
			}
			attacker, ok := facts.attackerARNs[tc.attackerKey]
			require.True(t, ok && attacker != "", "no fixture ARN for attacker key %q", tc.attackerKey)

			if tc.want {
				assertTP(t, ctx, db, facts, tc, attacker)
			} else {
				assertFP(t, ctx, db, tc, attacker)
			}
		})
	}

	// --- Step 5a: suite-level multi-edge count (folded from the former smoke test) ---
	// The smoke test asserted a single mega-user carried >=15 CAN_PRIVESC edges. The pathfinding
	// fixture has no such mega-user (one attacker per scenario), so the equivalent multi-edge
	// guarantee is expressed suite-wide: the total CAN_PRIVESC count across all fixture attackers
	// must be at least the number of common-tier TP cases (each must emit >=1 edge). The former
	// smoke test's distinct-target fan-out bound (<=10 targets) is intentionally NOT ported here:
	// assertTargetAllowlist (Step 6) is a strictly stronger guard — it allowlists the exact target
	// identities rather than merely bounding their count.
	t.Run("suite_multi_edge_count", func(t *testing.T) {
		wantTP := 0
		for _, tc := range labCases {
			if tc.want && tc.tier == tierCommon {
				wantTP++
			}
		}
		total := countEdges(t, ctx, db,
			`MATCH (a:Principal)-[r:CAN_PRIVESC]->()
			 WHERE a.Arn STARTS WITH 'arn:aws:iam:' AND a.Arn CONTAINS $prefix
			 RETURN count(r) AS n`,
			map[string]any{"prefix": facts.prefix})
		t.Logf("total CAN_PRIVESC edges from fixture attackers: %d (>= %d common-tier TP cases expected)", total, wantTP)
		assert.GreaterOrEqual(t, total, int64(wantTP),
			"total CAN_PRIVESC across fixture attackers (%d) must be >= the number of common-tier TP cases (%d)", total, wantTP)
	})

	// --- Step 5c: analysis-query path integration (folded from the former smoke test) ---
	// Run the registered aws/analysis/privesc_paths query and assert a known fixture attacker
	// surfaces as attacker_arn. The iam_put_role_policy attacker escalates to the :root-trusted
	// admin role (an _is_admin target), so it must appear in the admin-reachable paths — proving
	// the scoped CAN_PRIVESC edge is traversable end-to-end by the analysis layer.
	t.Run("analysis_query_finds_attacker", func(t *testing.T) {
		attacker, ok := facts.attackerARNs["iam_put_role_policy"]
		require.True(t, ok && attacker != "", "fixture must expose the iam_put_role_policy attacker")
		result, err := queries.RunPlatformQuery(ctx, db, "aws/analysis/privesc_paths", nil)
		require.NoError(t, err)
		require.NotNil(t, result)
		found := false
		for _, rec := range result.Records {
			if arn, _ := rec["attacker_arn"].(string); arn == attacker {
				found = true
				t.Logf("analysis found: %s -> %v (%v hops)", arn, rec["target_arn"], rec["hop_count"])
			}
		}
		assert.True(t, found,
			"iam_put_role_policy attacker (%s) must appear in aws/analysis/privesc_paths output", attacker)
	})

	// --- Step 5b: REAL-path HAS_ROLE verification (independent of CAN_PRIVESC) ---
	// For each provisioned backing resource, prove the REAL path INDEPENDENTLY of the
	// privesc method: (a) the collector enumerated the REAL resource — a :Resource node with the
	// right _resourceType and a REAL-ACCOUNT ARN (not the synthetic 000000000000 placeholder)
	// exists, and (b) resource_service_role/resource_to_role built (realResource)-[:HAS_ROLE]->(role)
	// to the expected privileged role. With synthetics still present (Step 2), this distinguishes
	// the real path: it asserts on the REAL ARN, never the synthetic one.
	realPathCases := []struct {
		name         string
		resourceType string
		realARN      string // the real fixture resource ARN/identifier (must NOT be 000000000000)
		roleARN      string // the expected HAS_ROLE target
	}{
		{"cfn_stack", "AWS::CloudFormation::Stack", fixture.Output("cfn_stack_id"), facts.computeAdminARN},
		{"cfn_stackset", "AWS::CloudFormation::StackSet", fixture.Output("cfn_stackset_id"), facts.computeAdminARN},
		{"ecs_taskdef", "AWS::ECS::TaskDefinition", fixture.Output("ecs_taskdef_arn"), facts.computeAdminARN},
		{"sfn_state_machine", "AWS::StepFunctions::StateMachine", fixture.Output("sfn_state_machine_arn"), facts.computeAdminARN},
		{"glue_job", "AWS::Glue::Job", fixture.Output("glue_job_name"), facts.computeAdminARN},
		{"codebuild_project", "AWS::CodeBuild::Project", fixture.Output("codebuild_project_arn"), facts.computeAdminARN},
		{"batch_jobdef", "AWS::Batch::JobDefinition", fixture.Output("batch_jobdef_arn"), facts.serviceAdminARNs["ecstasks"]},
	}
	for _, rc := range realPathCases {
		rc := rc
		t.Run("real_path/"+rc.name, func(t *testing.T) {
			require.NotEmpty(t, rc.realARN, "fixture must output a real ARN/id for %s", rc.name)
			require.NotContains(t, rc.realARN, "000000000000",
				"%s must be a REAL-account resource, not the synthetic placeholder", rc.name)

			// (a) the REAL resource node exists (collected), keyed by a real-account identifier.
			// Match by _resourceType AND that the node's arn contains the real account / matches the
			// real ARN/name — distinguishing it from the synthetic 000000000000 node of the same type.
			nNode := countEdges(t, ctx, db,
				`MATCH (r:Resource)
				 WHERE r._resourceType = $rt
				   AND coalesce(r.arn, r.Arn) IS NOT NULL
				   AND (coalesce(r.arn, r.Arn) = $arn OR coalesce(r.arn, r.Arn) CONTAINS $acct)
				 RETURN count(r) AS n`,
				map[string]any{"rt": rc.resourceType, "arn": rc.realARN, "acct": facts.account()})
			assert.Positive(t, nNode,
				"[REAL-PATH] no collected %s :Resource node with a real-account ARN found", rc.resourceType)

			// (b) the REAL resource node HAS_ROLE → the expected privileged role.
			nEdge := countEdges(t, ctx, db,
				`MATCH (r:Resource)-[:HAS_ROLE]->(role)
				 WHERE r._resourceType = $rt
				   AND coalesce(r.arn, r.Arn) CONTAINS $acct
				   AND (role.Arn = $role OR role.arn = $role)
				 RETURN count(*) AS n`,
				map[string]any{"rt": rc.resourceType, "acct": facts.account(), "role": rc.roleARN})
			assert.Positive(t, nEdge,
				"[REAL-PATH] real %s missing (Resource)-[:HAS_ROLE]->(%s)", rc.resourceType, rc.roleARN)
		})
	}

	// --- Step 6: Global no-fan-out / target-allowlist guard ---
	t.Run("global_no_cartesian_fanout", func(t *testing.T) {
		assertTargetAllowlist(t, ctx, db, facts)
	})
}

// assertTP verifies a TP case emits ≥1 CAN_PRIVESC edge to the expected target node (identity,
// not just count) for the named method. tgtStub asserts ≥1 edge for the method (fail-open
// service-wildcard / changeset methods MERGE onto a permission stub, so no clean identity).
func assertTP(t *testing.T, ctx context.Context, db graph.GraphDatabase, facts fixtureFacts, tc labCase, attacker string) {
	t.Helper()
	method, ok := peMethodLiteral(tc.methodID)
	require.True(t, ok, "could not extract pe.method literal for %s", tc.methodID)

	if tc.target == tgtStub {
		n := countEdges(t, ctx, db,
			`MATCH (a)-[r:CAN_PRIVESC {method:$method}]->()
			 WHERE a.Arn = $arn OR a.arn = $arn RETURN count(r) AS n`,
			map[string]any{"arn": attacker, "method": method})
		assert.Positive(t, n, "[TP FAIL] %s (%s) — %s", tc.methodID, method, tc.desc)
		return
	}

	target := facts.targetARN(tc)
	require.NotEmpty(t, target, "no expected target ARN resolved for %s", tc.attackerKey)
	n := countEdges(t, ctx, db,
		`MATCH (a)-[r:CAN_PRIVESC {method:$method}]->(v)
		 WHERE (a.Arn = $arn OR a.arn = $arn) AND (v.Arn = $target OR v.arn = $target)
		 RETURN count(r) AS n`,
		map[string]any{"arn": attacker, "method": method, "target": target})
	assert.Positive(t, n,
		"[TP FAIL] %s (%s) — expected edge %s → %s; %s", tc.methodID, method, attacker, target, tc.desc)
}

// assertFP verifies a FP case emits 0 CAN_PRIVESC edges for the named method (exact, by-method
// — sound under the multi-edge model: r.method = $method counts exactly THIS method's edges).
func assertFP(t *testing.T, ctx context.Context, db graph.GraphDatabase, tc labCase, attacker string) {
	t.Helper()
	if tc.methodID == m("iam_create_service_linked_role") {
		// No-op method has no {method:...} literal; assert the attacker has no CAN_PRIVESC at all.
		n := countEdges(t, ctx, db,
			`MATCH (a)-[r:CAN_PRIVESC]->() WHERE a.Arn = $arn OR a.arn = $arn RETURN count(r) AS n`,
			map[string]any{"arn": attacker})
		assert.Zero(t, n, "[FP FAIL] %s fired — %s", tc.methodID, tc.desc)
		return
	}
	method, ok := peMethodLiteral(tc.methodID)
	require.True(t, ok, "could not extract pe.method literal for %s — FP check would be vacuous", tc.methodID)
	n := countEdges(t, ctx, db,
		`MATCH (a)-[r:CAN_PRIVESC {method:$method}]->()
		 WHERE a.Arn = $arn OR a.arn = $arn RETURN count(r) AS n`,
		map[string]any{"arn": attacker, "method": method})
	assert.Zero(t, n,
		"[FP FAIL] %s (method=%q) fired for %s — %s", tc.methodID, method, attacker, tc.desc)
}

// assertTargetAllowlist proves no method fans out cartesian: every CAN_PRIVESC target from a
// fixture attacker must be a known passable target (self / admin role / a service-admin role /
// the compute role / the privileged user / a permission stub), never an arbitrary bystander
// principal. This replaces the weak count(DISTINCT target) <= 10 ("not huge") guard with a
// scoped allowlist ("scoped correctly") — task 10.
//
// Offender scope is restricted to THIS fixture's own `aur-pf-<id>-*` principals. The bfr
// account hosts many other live fixtures, and the 3c relationship seed keeps the non-fixture
// endpoint of any edge touching a fixture entity, so account-wide bystanders enter the graph
// and can receive CAN_PRIVESC from wildcard-Resource attackers — those are cross-fixture
// contamination, not a regression. A genuine cartesian fan-out would also reach this fixture's
// own principals (every attacker is fixture-prefixed), so prefix-scoping preserves the
// regression detection while ignoring foreign bystanders.
func assertTargetAllowlist(t *testing.T, ctx context.Context, db graph.GraphDatabase, facts fixtureFacts) {
	t.Helper()
	require.NotEmpty(t, facts.prefix, "fixture prefix must be set to scope the no-fan-out guard")
	allow := map[string]bool{
		facts.adminTargetARN:  true,
		facts.computeAdminARN: true,
		facts.privUserARN:     true,
	}
	for _, arn := range facts.serviceAdminARNs {
		allow[arn] = true
	}
	for _, arn := range facts.decoyARNs {
		allow[arn] = true // modifiable role targets (UpdateAssumeRolePolicy/AttachRolePolicy on "*")
	}
	for _, arn := range facts.attackerARNs {
		allow[arn] = true // self-loops + stub targets (permission edges point at the attacker's own action resources)
	}

	result, err := db.Query(ctx, `
		MATCH (a:Principal)-[:CAN_PRIVESC]->(v)
		WHERE a.Arn STARTS WITH 'arn:aws:iam:'
		RETURN DISTINCT coalesce(v.Arn, v.arn) AS target`, nil)
	require.NoError(t, err)

	var off []string
	for _, rec := range result.Records {
		target, _ := rec["target"].(string)
		if target == "" {
			continue // stub :Resource targets (service-wildcard / changeset) carry no IAM ARN
		}
		// Principal (IAM ARN) targets must be in the allowlist; non-Principal resource stubs
		// (e.g. a service ARN) are the fail-open methods' legitimate targets. Only this
		// fixture's own `aur-pf-<id>-*` principals are in scope — foreign bystanders pulled in
		// by the shared account are ignored (see the function doc).
		if strings.HasPrefix(target, "arn:aws:iam:") && strings.Contains(target, facts.prefix) && !allow[target] {
			off = append(off, target)
		}
	}
	assert.Empty(t, off,
		"CAN_PRIVESC reached IAM principals outside the passable-target allowlist — cartesian fan-out regression: %v", off)
}

// resourceReferencesPrefix reports whether a collected resource is owned by THIS fixture: its
// role-bearing properties (or top-level Role/IamInstanceProfile) reference a fixture role whose
// ARN carries the run prefix (aur-pf-<id>). Used to bound the seeded graph against the shared
// account's other live fixtures.
func resourceReferencesPrefix(r output.AWSResource, prefix string) bool {
	if prefix == "" {
		return false
	}
	if strings.Contains(r.ARN, prefix) {
		return true
	}
	for _, v := range r.Properties {
		if s, ok := v.(string); ok && strings.Contains(s, prefix) {
			return true
		}
	}
	return false
}

func countEdges(t *testing.T, ctx context.Context, db graph.GraphDatabase, cypher string, params map[string]any) int64 {
	t.Helper()
	result, err := db.Query(ctx, cypher, params)
	require.NoError(t, err)
	if len(result.Records) == 0 {
		return 0
	}
	switch v := result.Records[0]["n"].(type) {
	case int64:
		return v
	case int:
		return int64(v)
	case float64:
		return int64(v)
	}
	return 0
}
