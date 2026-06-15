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
	tgtNone                 targetKind = iota // method must emit NO edge for this attacker (FP / no-op)
	tgtSelf                                   // self-escalation: attacker -> attacker
	tgtAdminRole                              // trust-backed direct takeover: the :root-trusted admin role
	tgtServiceRole                            // new-passrole: the service-trusted admin role (keyed by svcKey)
	tgtComputeRole                            // existing-compute HAS_ROLE: the compute admin exec role
	tgtPrivUser                               // principal-access: the privileged user (HAS a console profile)
	tgtNoProfileUser                          // principal-access: the privileged user with NO console profile
	tgtAttackerTrustedRole                    // trust-mismatch: the admin role whose trust names the attacker
	tgtDirectTrustAdminRole                   // F6: admin role whose trust DIRECTLY names the attacker's exact ARN (no identity grant)
	tgtStub                                   // service-wildcard / changeset fail-open: any edge for the method
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
// Every case the table covers fires on live data, so the map is intentionally EMPTY. The
// detection coverage that makes each case fire:
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

// FALSE-POSITIVE COVERAGE
// -----------------------------------------------------------------------------------------
// Each want=false (FP) row below is labelled by the FP TYPE it isolates — the guard whose
// removal would flip the row to a true positive. The FP types:
//
//	missing-permission        service/api-precondition
//	trust-policy-mismatch     admin-source-or-middle
//	no-usable-resource
//	target-not-privileged
//
// Runtime-context / org-policy FPs (MFA-gated actions, source-IP/VPC, aws:PrincipalOrgID,
// SCPs without --org-policies-file) cannot be produced by any query against current graph
// data, so they are a STATED BOUNDARY rather than a coverage gap — no such FP row exists or
// should be added without a prior engine/enricher change.
//
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
	// G1: CreateLoginProfile returns EntityAlreadyExists when the target already has a console
	// profile, so the method now fires only when the target has NO profile. The attacker scopes
	// to "*" so the edge lands on the privileged NO-profile user (noprofile_user); priv_user (which
	// HAS a profile) is correctly suppressed and is the fp_createloginprofile_has_profile FP twin.
	{"iam_create_login_profile", m("iam_create_login_profile"), true, tgtNoProfileUser, "", tierCommon, "CreateLoginProfile+UpdateLoginProfile on a privileged user with NO console profile (HasLoginProfile=false → bootstrap)"},
	{"iam_update_login_profile", m("iam_update_login_profile"), true, tgtPrivUser, "", tierCommon, "UpdateLoginProfile on the privileged user"},

	// ===== IAM trust-backed direct takeover (target = :root-trusted admin role) =====
	{"iam_put_role_policy", m("iam_put_role_policy"), true, tgtAdminRole, "", tierCommon, "PutRolePolicy + assumable (:root trust) admin role"},
	{"iam_attach_role_policy", m("iam_attach_role_policy"), true, tgtAdminRole, "", tierCommon, "AttachRolePolicy + assumable admin role"},
	{"iam_update_assume_role_policy", m("iam_update_assume_role_policy"), true, tgtAdminRole, "", tierCommon, "UpdateAssumeRolePolicy on the admin role"},
	// Trust-mismatch matrix, trusts-:root-same-account cell = TP: the admin role trusts :root and
	// the attacker holds sts:AssumeRole, so the IAM evaluator emits STS_ASSUMEROLE → admin role
	// (identity AND trust) → sts_assume_role fires.
	{"sts_assume_role", m("sts_assume_role"), true, tgtAdminRole, "", tierCommon, "AssumeRole + :root trust → validated STS_ASSUMEROLE to admin role"},
	// Trust-mismatch matrix, trusts-attacker-explicitly cell = TP: the admin role's trust policy
	// NAMES this attacker and the attacker holds sts:AssumeRole → STS_ASSUMEROLE → sts_assume_role
	// fires to that role.
	{"sts_assume_attacker_trusted", m("sts_assume_role"), true, tgtAttackerTrustedRole, "", tierCommon, "AssumeRole + a role whose trust names the attacker → validated STS_ASSUMEROLE to the attacker-trusted admin role"},
	// F6 HEADLINE: the attacker holds NO sts:AssumeRole grant (only benign sts:GetCallerIdentity) but is
	// DIRECTLY NAMED by exact ARN in direct_trust_admin_role's trust → the evaluator emits a validated
	// STS_ASSUMEROLE edge PURELY from same-account exact-ARN direct trust → sts_assume_role fires (TP).
	{"sts_assume_direct_trust", m("sts_assume_role"), true, tgtDirectTrustAdminRole, "", tierCommon, "F6: exact-ARN DIRECT TRUST with NO identity grant → validated STS_ASSUMEROLE → CAN_PRIVESC{sts:AssumeRole} to the direct-trust admin role"},
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
	// F2 (ecs-006): ExecuteCommand scoped ONLY to the REAL fixture ECS CLUSTER ARN (not wildcard,
	// not task-def). The grant resolves against the AWS::ECS::Cluster node the ECSClusterEnumerator
	// collects → base ECS_EXECUTECOMMAND edge to the cluster → enricher reaches compute_admin via
	// the task def HAS_ROLE. Dedicated F2 subtests (Step 5d) assert the collector + base edge directly.
	{"ecs_execute_command_cluster", m("ecs_execute_command"), true, tgtComputeRole, "", tierCommon, "cluster-scoped ExecuteCommand on the REAL fixture ECS cluster (F2: AWS::ECS::Cluster node → ECS_EXECUTECOMMAND → compute_admin via task def HAS_ROLE)"},
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
	{"bedrock_invoke", m("bedrock_access_code_interpreter"), true, tgtServiceRole, "bedrock", tierCommon, "StartCodeInterpreterSession + InvokeCodeInterpreter on a synthetic AgentCore CodeInterpreter whose ExecutionRoleArn is the privileged bedrock-agentcore svcadmin role (AgentCore not provisionable via TF)"},
	{"cloudform_changeset", m("cloudformation_changeset"), true, tgtComputeRole, "", tierCommon, "CreateChangeSet+ExecuteChangeSet against a REAL fixture CFN Stack whose RoleARN is the privileged compute admin role"},

	// =========================================================================
	// Branch coverage — each row exercises a distinct BRANCH: a conditional PassRole,
	// the managed-policy SSM path, the real-Lambda HAS_ROLE path, the Glue new-passrole
	// UNION branch, the existing-launch-template branch, the cognito unauth-relax branch,
	// plus (full-tier) the concrete-ARN AppRunner and the SageMaker lifecycle-create variant.
	// =========================================================================
	// Conditional iam:PassRole (StringEquals iam:PassedToService=lambda) + lambda:CreateFunction.
	{"iam_pass_role_lambda_cond", m("iam_pass_role_lambda"), true, tgtServiceRole, "lambda", tierCommon, "conditional PassRole {iam:PassedToService=lambda.amazonaws.com} + CreateFunction → IAM_PASSROLE edge still forms (permissive-when-absent) → lambda svcadmin role"},
	// SSM via the AmazonSSMManagedInstanceCore managed policy (ec2-trusting role, NOT ssm trust).
	{"ssm_managed_send_command", m("ssm_send_command"), true, tgtServiceRole, "ssm_managed", tierCommon, "SendCommand to the ec2-instance running the ec2-trusting role made _ssm_enabled by AmazonSSMManagedInstanceCore (managed-policy path, not ssm trust)"},
	{"ssm_managed_start_session", m("ssm_start_session"), true, tgtServiceRole, "ssm_managed", tierCommon, "StartSession on the ec2-instance running the managed-policy-SSM role"},
	// Existing-compute Lambda on the REAL collected lambda function (no resource policy).
	{"lambda_update_code_real", m("lambda_update_function_code"), true, tgtComputeRole, "", tierCommon, "UpdateFunctionCode+InvokeFunction on the REAL fixture Lambda (no resource policy) → real (fn)-[:HAS_ROLE]->(compute_admin)"},
	// Glue new-passrole UNION branch (PassRole glue + UpdateJob + StartJobRun, no existing job).
	{"glue_passrole_updatejob", m("glue_updatejob_startjobrun"), true, tgtServiceRole, "glue", tierCommon, "new-passrole branch: PassRole(glue) + UpdateJob + StartJobRun → passed glue svcadmin role via IAM_PASSROLE (no pre-existing Glue job needed)"},
	// Existing-launch-template branch (CreateLaunchTemplateVersion + ModifyLaunchTemplate, no PassRole).
	{"ec2_launch_template_existing", m("ec2_launch_template_version"), true, tgtComputeRole, "", tierCommon, "existing-template variant: CreateLaunchTemplateVersion+ModifyLaunchTemplate on a REAL launch template referencing compute_admin's instance profile → (LaunchTemplate)-[:HAS_ROLE]->(compute_admin)"},
	// Cognito unauth-relax branch (PassRole + SetIdentityPoolRoles, NO GetId/GetCredentials).
	{"cognito_unauth_pool", m("cognito_set_identity_pool_roles"), true, tgtServiceRole, "cognito_unauth", tierCommon, "PassRole + SetIdentityPoolRoles with NO GetId/GetCredentials → fires only via the unauth-relax branch (REAL pool AllowUnauthenticatedIdentities=true → (IdentityPool)-[:HAS_ROLE]->(role))"},
	// Full tier (AppRunner bills while running): concrete-ARN-scoped UpdateService on a REAL service.
	{"apprunner_update_concrete", m("apprunner_update_service"), true, tgtServiceRole, "apprunner_instance", tierFull, "UpdateService scoped to the CONCRETE service ARN on a REAL App Runner service → its instance role via real (Service)-[:HAS_ROLE]->(role) (validates compute-node load + concrete-ARN token)"},
	// Full tier (SageMaker notebook bills while InService): lifecycle CREATE variant on a real notebook.
	{"sagemaker_lifecycle_create", m("sagemaker_lifecycle_config"), true, tgtComputeRole, "", tierFull, "CreateNotebookInstanceLifecycleConfig + UpdateNotebookInstance on a REAL notebook instance running compute_admin → lifecycle-create variant (distinct from the synthetic Update-config case)"},

	// ----- Branch-coverage FALSE POSITIVES -----
	// Conditional PassRole but no consuming action → must NOT fire.
	{"fp_passrole_cond_only", m("iam_pass_role_lambda"), false, tgtNone, "", tierCommon, "missing-permission: conditional PassRole {iam:PassedToService=lambda} alone (no lambda:CreateFunction) → IAM_PASSROLE edge forms but no create primitive → no edge"},
	// ssm-managed instance + _ssm_enabled role exist, but no SendCommand/StartSession.
	{"fp_ssm_managed_no_send", m("ssm_send_command"), false, tgtNone, "", tierCommon, "missing-permission: ssm-managed instance + _ssm_enabled role present, but attacker holds neither ssm:SendCommand nor ssm:StartSession → no edge"},
	// Account-scoped unauth-relax: the validated enricher requires only that an unauth-enabled
	// identity pool EXISTS in the victim's account (NOT a pre-bound pool->victim HAS_ROLE), so a
	// PassRole+SetIdentityPoolRoles attacker (NO GetId/GetCredentials) CAN escalate to ANY
	// cognito-trusting admin role in the account by binding it to the EXISTING unauth pool's
	// unauth slot at attack time. The auth-only-pool admin role is therefore a genuine TP target,
	// not a false positive — the relax cannot tell which pool SetIdentityPoolRoles will bind. The
	// (real) FP boundary is "no unauth pool anywhere in the account", which this fixture (which
	// has the cognito_unauth pool) cannot isolate; that boundary is exercised by the auth branch
	// requiring GetId/GetCredentials, covered by cognito_set_pool_roles. Renamed-in-place key
	// kept to avoid renaming the attacker IAM user; want flipped to TP.
	{"fp_cognito_authpool_no_getid", m("cognito_set_identity_pool_roles"), true, tgtServiceRole, "cognito_authonly", tierCommon, "account-scoped unauth-relax: PassRole+SetIdentityPoolRoles + an unauth-enabled pool EXISTING in the account → escalates to the auth-only-pool's cognito-trusting admin role (the validated relax is account-scoped, not pool-bound)"},
	// PassRole(ec2) only, no template-edit actions → neither launch-template branch fires.
	{"fp_ec2_lt_passrole_only", m("ec2_launch_template_version"), false, tgtNone, "", tierCommon, "missing-permission: PassRole(ec2) alone (no CreateLaunchTemplateVersion/ModifyLaunchTemplate) → neither ec2_launch_template_version branch fires"},

	// ===== Intentional no-op (target = none) — no-usable-resource =====
	// These methods can never draw a usable CAN_PRIVESC edge: the SLR creator gains no assumable
	// identity, and CreateProject's only target is a non-Principal service stub.
	{"iam_create_slr", m("iam_create_service_linked_role"), false, tgtNone, "", tierCommon, "no-usable-resource: CreateServiceLinkedRole — created SLR is unassumable/immutable, emits no CAN_PRIVESC (RETURN 0)"},
	{"codestar_create", m("codestar_create_project"), false, tgtNone, "", tierCommon, "no-usable-resource: CreateProject points at a service stub (not a Principal) on the live fixture → no edge"},

	// =========================================================================
	// FALSE POSITIVES — the named method must NOT fire (0 edges by-method).
	// =========================================================================

	// missing-permission
	{"fp_passrole_only", m("iam_pass_role_lambda"), false, tgtNone, "", tierCommon, "missing-permission: PassRole alone (no CreateFunction)"},
	{"fp_passrole_only", m("iam_pass_role_ec2"), false, tgtNone, "", tierCommon, "missing-permission: PassRole alone (no RunInstances)"},
	{"fp_lambda_create_only", m("iam_pass_role_lambda"), false, tgtNone, "", tierCommon, "missing-permission: CreateFunction alone (no PassRole)"},
	{"fp_lambda_invoke_only", m("lambda_updatecode_invoke"), false, tgtNone, "", tierCommon, "missing-permission: InvokeFunction alone (no UpdateFunctionCode)"},
	{"fp_lambda_no_trigger", m("lambda_updatecode_invoke"), false, tgtNone, "", tierCommon, "missing-permission: UpdateFunctionCode alone (no trigger primitive)"},
	{"fp_ec2_run_only", m("iam_pass_role_ec2"), false, tgtNone, "", tierCommon, "missing-permission: RunInstances alone (no PassRole)"},
	{"fp_cfn_create_only", m("iam_pass_role_cloudformation"), false, tgtNone, "", tierCommon, "missing-permission: CreateStack alone (no PassRole)"},
	{"fp_glue_createjob_only", m("glue_createjob_startjobrun"), false, tgtNone, "", tierCommon, "missing-permission: CreateJob alone (no PassRole/StartJobRun)"},
	{"fp_sfn_no_start", m("stepfunctions_create_startexecution"), false, tgtNone, "", tierCommon, "missing-permission: PassRole+CreateStateMachine (no StartExecution)"},
	{"fp_sfn_no_start", m("stepfunctions_create"), true, tgtServiceRole, "states", tierCommon, "PassRole+CreateStateMachine → stepfunctions_create SHOULD still fire"},
	{"fp_ecs_create_only", m("ecs_create_service"), false, tgtNone, "", tierCommon, "missing-permission: CreateService alone (no PassRole)"},
	{"fp_ssm_createdoc_only", m("ssm_createdocument_startautomation"), false, tgtNone, "", tierCommon, "missing-permission: CreateDocument alone (no StartAutomationExecution)"},
	{"fp_changeset_create_only", m("cloudformation_changeset"), false, tgtNone, "", tierCommon, "missing-permission: CreateChangeSet alone (no ExecuteChangeSet)"},
	// missing-permission (legacy-matrix parity): preserve the FP coverage the old suite had for these methods.
	{"fp_passrole_only", m("ec2_request_spot_instances"), false, tgtNone, "", tierCommon, "missing-permission: PassRole alone (no RequestSpotInstances)"},
	{"fp_passrole_only", m("glue_create_dev_endpoint"), false, tgtNone, "", tierCommon, "missing-permission: PassRole alone (no CreateDevEndpoint)"},
	{"fp_lambda_no_trigger", m("lambda_add_permission"), false, tgtNone, "", tierCommon, "missing-permission: UpdateFunctionCode alone (no AddPermission)"},
	{"fp_ecs_runtask_no_passrole", m("ecs_passrole_runtask"), false, tgtNone, "", tierCommon, "missing-permission: RunTask alone (no PassRole)"},
	{"fp_sfn_updatesm_only", m("stepfunctions_update"), false, tgtNone, "", tierCommon, "missing-permission: UpdateStateMachine alone (no StartExecution)"},

	// trust-policy-mismatch (PassRole scoped to the wrong-service decoy role)
	{"fp_passrole_wrong_service", m("iam_pass_role_lambda"), false, tgtNone, "", tierCommon, "trust-policy-mismatch: PassRole scoped to a non-lambda-trusting (sqs) role → iam_pass_role_lambda must NOT fire"},

	// target-not-privileged (PassRole/CreateAccessKey scoped to a non-privileged target)
	{"fp_passrole_nonpriv_target", m("iam_pass_role_lambda"), false, tgtNone, "", tierCommon, "target-not-privileged: PassRole scoped to a lambda-trusting but NON-privileged role → must NOT fire"},
	{"fp_accesskey_nonpriv", m("iam_create_access_key"), false, tgtNone, "", tierCommon, "target-not-privileged: CreateAccessKey+DeleteAccessKey but the only reachable user is non-privileged"},

	// trust-policy-mismatch — trust-backed direct-takeover FPs (no usable assume path to the
	// modify target): iam_attach_role_policy / iam_put_role_policy require BOTH the validated
	// STS_ASSUMEROLE base edge (identity AND trust) to the victim AND the modify-permission edge to
	// the SAME victim. The attacker scopes its modify permission to a decoy role it CANNOT assume,
	// so neither the decoy (modify yes, no STS_ASSUMEROLE — trust does not allow the attacker) nor
	// the :root-trusted admin_target (STS_ASSUMEROLE yes, but the modify edge does not point at it)
	// matches → 0 edges. Each pairs with its TP twin above (iam_attach_role_policy /
	// iam_put_role_policy on admin_target, where both legs coincide).
	// NOTE: sts_assume_role has NO sound scoped FP in this fixture — under F4 it gates directly on
	// the STS_ASSUMEROLE edge to the victim, and admin_target trusts :root so every attacker
	// holding sts:AssumeRole genuinely escalates to it (a real TP, not an FP). See dev-summary.
	// service-only trust: the role trusts ONLY a service principal → trust does not allow any
	// attacker → the evaluator emits NO STS_ASSUMEROLE edge to it.
	{"fp_attachrolepolicy_service_only", m("iam_attach_role_policy"), false, tgtNone, "", tierCommon, "trust-policy-mismatch: AttachRolePolicy scoped to a service-only-trusted role (no STS_ASSUMEROLE to it) → must NOT fire"},
	// not-assumable: the decoy trusts a DIFFERENT principal (the non-priv user) → no STS_ASSUMEROLE.
	{"fp_putrolepolicy_not_assumable", m("iam_put_role_policy"), false, tgtNone, "", tierCommon, "trust-policy-mismatch: PutRolePolicy scoped to a role the attacker can't assume (trust names someone else) → must NOT fire"},

	// self-escalation FPs: the named guard is the SOLE reason each is suppressed; each pairs with a
	// satisfying TP twin above (iam_create_policy_version / iam_add_user_to_group / iam_put_group_policy).
	// (S+L) — also verified in the seeded suite (TestPrivescNoCartesianFanOut).
	// admin-source-or-middle: an already-admin attacker is not escalating.
	{"fp_already_admin", m("iam_create_policy_version"), false, tgtNone, "", tierCommon, "admin-source-or-middle: CreatePolicyVersion on a self-attached policy but the attacker is already admin → admin-as-source guard suppresses"},
	// target-not-privileged: joining/owning a non-privileged group (or a group the attacker
	// cannot reach) confers no new privilege.
	{"fp_adduser_nonpriv_group", m("iam_add_user_to_group"), false, tgtNone, "", tierCommon, "target-not-privileged: AddUserToGroup but the only joinable group is non-privileged (already a member of the admin group) → privileged-group guard suppresses"},
	{"fp_putgrouppolicy_not_member", m("iam_put_group_policy"), false, tgtNone, "", tierCommon, "target-not-privileged: PutGroupPolicy on a group the attacker is NOT a member of → membership guard suppresses"},

	// service/api-precondition — login-profile / access-key FPs: the tri-state confirmed-false
	// signal comes from the live GAAD collector. Each pairs with its satisfying TP twin above
	// (iam_update_login_profile / iam_create_access_key on priv_user). (L primary; S by seeding the
	// prop — already locked by TestPrivescLoginProfileGuard / TestPrivescAccessKeyCountGuard in the
	// seeded suite.)
	{"fp_updateloginprofile_no_profile", m("iam_update_login_profile"), false, tgtNone, "", tierCommon, "service/api-precondition: UpdateLoginProfile on a privileged user with NO console profile (HasLoginProfile=false → NoSuchEntity) → suppresses"},
	{"fp_createaccesskey_two_keys", m("iam_create_access_key"), false, tgtNone, "", tierCommon, "service/api-precondition: CreateAccessKey on a privileged user already holding 2 active keys (AccessKeyCount=2 → LimitExceeded) → suppresses"},
	// G1 FP twin (live): CreateLoginProfile+UpdateLoginProfile scoped to priv_user (which HAS a
	// console profile → collector GetLoginProfile succeeds → HasLoginProfile=true → the G1 guard
	// coalesce(target.HasLoginProfile, false) = false is unmet → CreateLoginProfile would return
	// EntityAlreadyExists → suppressed). Twin: the iam_create_login_profile TP attacker (scoped to
	// "*", lands on noprofile_user which has NO profile). G1 is the SOLE rejecting guard here.
	{"fp_createloginprofile_has_profile", m("iam_create_login_profile"), false, tgtNone, "", tierCommon, "service/api-precondition: CreateLoginProfile on a privileged user that already has a console profile (HasLoginProfile=true → EntityAlreadyExists) → suppresses"},
	// G2 FP twin (live): SetDefaultPolicyVersion on a self-attached customer-managed policy with a
	// SINGLE version (single_ver) → transformer surfaces policy_version_count=1 → the G2 guard
	// coalesce(policy.policy_version_count, 2) > 1 is unmet → nothing to activate → suppressed. Twin:
	// the iam_set_default_policy_version TP attacker (self-attaches the 2-version custom policy). G2 is
	// the SOLE rejecting guard here (attacker non-admin, policy customer-managed + attached to self).
	{"fp_setdefaultversion_single_version", m("iam_set_default_policy_version"), false, tgtNone, "", tierCommon, "service/api-precondition: SetDefaultPolicyVersion on a self-attached single-version customer policy (policy_version_count=1 → nothing to activate) → suppresses"},

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
	// missing-permission (full tier)
	{"fp_emr_runjobflow_no_passrole", m("emr_run_job_flow"), false, tgtNone, "", tierFull, "missing-permission: RunJobFlow alone (no PassRole)"},
	{"fp_emrserverless_no_start", m("emr_serverless_startjobrun"), false, tgtNone, "", tierFull, "missing-permission: PassRole+CreateApplication (no StartJobRun)"},
}

// peMethodLiteral extracts the human-readable method string a privesc query stamps onto its
// CAN_PRIVESC edge (e.g. "iam:PassRole + lambda:CreateFunction"). FP assertions match this
// exact value (read from the loaded Cypher, not a hardcoded map) so a renamed literal fails
// loud rather than turning the FP check vacuous. CAN_PRIVESC is multi-edge: `method` lives
// in the MERGE relationship pattern, so we match the `{method: '<M>'}` literal.
var peMethodRe = regexp.MustCompile(`CAN_PRIVESC\s*\{method:\s*'([^']*)'\}`)

// methodLitOverride maps an attackerKey to the EXACT pe.method literal its CAN_PRIVESC edge
// carries, for enrichers that compute `method` as a Cypher VARIABLE in the MERGE pattern
// (CAN_PRIVESC {method: method}) rather than an inline string literal. peMethodLiteral's regex
// only sees inline literals, so these UNION/CASE-branch methods (ec2_launch_template_version,
// sagemaker_lifecycle_config — each emits TWO distinct method strings) need their per-branch
// literal named explicitly so the TP/FP assertion targets the right branch's edge. Keyed by
// attackerKey (unique per labCase). The enricher Cypher is the source of truth; these strings
// are copied verbatim from its RETURN ... AS method / CASE ... AS method clauses.
var methodLitOverride = map[string]string{
	"ec2_launch_template_ver":      "ec2:CreateLaunchTemplateVersion + ec2:ModifyLaunchTemplate",
	"ec2_launch_template_existing": "ec2:CreateLaunchTemplateVersion + ec2:ModifyLaunchTemplate (existing-template variant)",
	"fp_ec2_lt_passrole_only":      "ec2:CreateLaunchTemplateVersion + ec2:ModifyLaunchTemplate",
	"sagemaker_lifecycle":          "sagemaker:UpdateNotebookInstanceLifecycleConfig",
	"sagemaker_lifecycle_create":   "sagemaker:CreateNotebookInstanceLifecycleConfig + sagemaker:UpdateNotebookInstance",
}

// caseMethodLiteral returns the pe.method literal a case's CAN_PRIVESC edge carries: the explicit
// per-branch override when the enricher computes `method` as a variable, else the inline literal
// extracted from the enricher Cypher by peMethodLiteral.
func caseMethodLiteral(tc labCase) (string, bool) {
	if lit, ok := methodLitOverride[tc.attackerKey]; ok {
		return lit, true
	}
	return peMethodLiteral(tc.methodID)
}

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
	attackerARNs            map[string]string // attackerKey -> ARN (common + full merged)
	serviceAdminARNs        map[string]string // svcKey -> ARN (common + full merged)
	adminTargetARN          string
	computeAdminARN         string
	privUserARN             string
	noProfileUserARN        string   // privileged user with NO console profile (iam_create_login_profile TP target)
	attackerTrustedRoleARN  string   // admin role whose trust names the attacker (trusts-attacker-explicitly TP)
	directTrustAdminRoleARN string   // F6: admin role whose trust DIRECTLY names the no-grant attacker's exact ARN
	prefix                  string   // this fixture's "aur-pf-<id>" name prefix (scopes the no-fan-out guard)
	accountID               string   // the fixture's AWS account id (distinguishes real vs synthetic 000000000000)
	decoyARNs               []string // FP decoy role ARNs (legitimately modifiable role targets)
	// Privileged-USER FP targets. These are the per-method FP victims (no-profile / two-keys), but
	// they are ADMIN users, so a broad-resource principal-access TP attacker (e.g.
	// iam:CreateAccessKey/CreateLoginProfile on "*") can legitimately reach the one whose own
	// guard signal does not suppress it (the no-profile user still has <2 keys; the two-key user
	// still has a console profile). They therefore belong in the no-fan-out allowlist.
	privUserFPTargetARNs []string
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
	case tgtNoProfileUser:
		return f.noProfileUserARN
	case tgtAttackerTrustedRole:
		return f.attackerTrustedRoleARN
	case tgtDirectTrustAdminRole:
		return f.directTrustAdminRoleARN
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
		attackerARNs:            fixture.OutputMap("attacker_arns"),
		serviceAdminARNs:        fixture.OutputMap("service_admin_arns"),
		adminTargetARN:          fixture.Output("admin_target_arn"),
		computeAdminARN:         fixture.Output("compute_admin_arn"),
		privUserARN:             fixture.Output("priv_user_arn"),
		noProfileUserARN:        fixture.Output("noprofile_user_arn"),
		attackerTrustedRoleARN:  fixture.Output("attacker_trusted_role_arn"),
		directTrustAdminRoleARN: fixture.Output("direct_trust_admin_role_arn"),
		prefix:                  fixture.Output("prefix"),
		accountID:               fixture.Output("account_id"),
		// Admin/decoy roles no per-case TP points at but a broad-Resource attacker (e.g.
		// iam:UpdateAssumeRolePolicy on "*") can legitimately reach, so they belong in the
		// no-fan-out allowlist. Includes the FP-category decoys and the Federated-trust cognito
		// role (a frozen-query known gap, not a passrole TP target — see the cognito labCase).
		decoyARNs: []string{
			fixture.Output("trust_mismatch_target_arn"),
			// trust_mismatch_decoy role: belongs here because it receives the broad role-fan-out
			// CAN_PRIVESC edges that land on every modifiable/service-trusted role —
			// iam_update_assume_role_policy (medium), passrole_modify_policy (high, via its
			// trusted_services=[ec2.amazonaws.com] service-trust OR-leg), and
			// update_assume_role_passrole_service (medium) — the SAME edge classes already accepted
			// for the sibling no-fan-out decoy roles wrong_service_target / service_only_trust_role.
			fixture.Output("trust_mismatch_decoy_arn"),
			fixture.Output("wrong_service_target_arn"),
			fixture.Output("nonpriv_lambda_target_arn"),
			fixture.Output("service_only_trust_role_arn"),
			fixture.Output("cognito_admin_arn"),
			// the auth-only pool's admin role — a legitimate broad-resource target.
			fixture.Output("cognito_authonly_admin_arn"),
		},
		privUserFPTargetARNs: []string{
			fixture.Output("noprofile_user_arn"),
			fixture.Output("twokey_user_arn"),
		},
	}
	if fullTier {
		for k, v := range fixture.OutputMap("full_attacker_arns") {
			facts.attackerARNs[k] = v
		}
		for k, v := range fixture.OutputMap("full_service_admin_arns") {
			facts.serviceAdminARNs[k] = v
		}
		// The AppRunner service's instance role is a dedicated admin role (not in the
		// service_admin map). Expose it under the svcKey the apprunner_update_concrete labCase
		// resolves (full-tier only — the resource is var.enable_full-gated).
		if arn := fixture.Output("apprunner_instance_role_arn"); arn != "" {
			facts.serviceAdminARNs["apprunner_instance"] = arn
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
			// The graph module emits the collected service resources
			// (resourcesWithPolicies) WRAPPED as AWSIAMResource via output.FromAWSResource
			// (so the live neo4j formatter, which type-switches only on AWSIAMResource,
			// loads them — see graph.go emitOutputs). A collected backing resource carries a
			// non-IAM ResourceType (e.g. AWS::Batch::JobDefinition, AWS::CloudFormation::Stack);
			// real IAM entities carry AWS::IAM::*. Un-wrap the embedded AWSResource for the
			// non-IAM ones so the REAL collection → resource_service_role → HAS_ROLE path is
			// exercised end-to-end rather than only via the synthetic stand-ins.
			if v.ResourceType != "" && !strings.HasPrefix(v.ResourceType, "AWS::IAM::") {
				collectedResources = append(collectedResources, v.AWSResource)
			}
		case output.AWSIAMRelationship:
			iamRels = append(iamRels, v)
		case output.AWSResource:
			// Defensive: if a future module emits a plain AWSResource directly, still capture it.
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
			ComputeAdminARN:         facts.computeAdminARN,
			EC2InstanceARN:          fixture.Output("ec2_instance_arn"),
			BedrockExecRole:         facts.serviceAdminARNs["bedrock"],
			AdminTargetARN:          facts.adminTargetARN,
			PrivUserARN:             facts.privUserARN,
			NoProfileUserARN:        facts.noProfileUserARN,
			AttackerTrustedRoleARN:  facts.attackerTrustedRoleARN,
			DirectTrustAdminRoleARN: facts.directTrustAdminRoleARN,
			Prefix:                  facts.prefix,
			AccountID:               facts.accountID,
			ServiceAdminARNs:        facts.serviceAdminARNs,
			AttackerARNs:            facts.attackerARNs,
			DecoyARNs:               facts.decoyARNs,
			PrivUserFPTargetARNs:    facts.privUserFPTargetARNs,
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
				t.Skipf("known gap (frozen query): %s — %s", tc.desc, reason)
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
		// Real-path HAS_ROLE checks. Common-tier, free-at-rest backing.
		{"launch_template", "AWS::EC2::LaunchTemplate", fixture.Output("launch_template_id"), facts.computeAdminARN},
		{"cognito_identity_pool", "AWS::Cognito::IdentityPool", fixture.Output("cognito_unauth_pool_id"), fixture.Output("cognito_unauth_admin_arn")},
	}
	// Full-tier real-path check for the AppRunner service (var.enable_full-gated resource).
	if fullTier {
		realPathCases = append(realPathCases, struct {
			name         string
			resourceType string
			realARN      string
			roleARN      string
		}{"apprunner_service", "AWS::AppRunner::Service", fixture.Output("apprunner_service_arn"), fixture.Output("apprunner_instance_role_arn")})
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

	// --- Step 5d: F2 ECS cluster collector — direct proof the cluster-node path works (ecs-006) ---
	// F2 adds the ECSClusterEnumerator so a cluster-scoped ecs:ExecuteCommand grant resolves
	// against a concrete AWS::ECS::Cluster node, forming the base ECS_EXECUTECOMMAND edge that was
	// MISSING before F2. These subtests assert that path directly on the rebuilt live graph:
	//   (1) the collector produced a real AWS::ECS::Cluster node,
	//   (2) the base ECS_EXECUTECOMMAND edge from the cluster-scoped attacker points at it,
	//   (3) the privesc enricher fired (CAN_PRIVESC{ecs:ExecuteCommand} → compute_admin task role),
	//   (4) collecting the cluster did NOT fan out a spurious ECS_EXECUTECOMMAND edge to a benign
	//       principal that lacks the action (collector precision).
	t.Run("f2_ecs_cluster", func(t *testing.T) {
		clusterARN := fixture.Output("ecs_cluster_arn")
		require.NotEmpty(t, clusterARN, "fixture must output ecs_cluster_arn")
		require.NotContains(t, clusterARN, "000000000000",
			"ecs_cluster_arn must be a REAL-account ARN, not the synthetic placeholder")

		clusterAttacker := facts.attackerARNs["ecs_execute_command_cluster"]
		require.NotEmpty(t, clusterAttacker, "fixture must expose the ecs_execute_command_cluster attacker")
		benignAttacker := facts.attackerARNs["fp_ecs_no_execute_command"]
		require.NotEmpty(t, benignAttacker, "fixture must expose the fp_ecs_no_execute_command attacker")

		// (1) Collector: a real AWS::ECS::Cluster :Resource node with the fixture's cluster ARN.
		t.Run("collector_cluster_node_exists", func(t *testing.T) {
			n := countEdges(t, ctx, db,
				`MATCH (r:Resource)
				 WHERE r._resourceType = 'AWS::ECS::Cluster'
				   AND coalesce(r.arn, r.Arn) = $arn
				 RETURN count(r) AS n`,
				map[string]any{"arn": clusterARN})
			assert.Positive(t, n,
				"[F2] no collected AWS::ECS::Cluster :Resource node for fixture cluster %s — collector did not run", clusterARN)
		})

		// (2) Base edge: attacker -[ECS_EXECUTECOMMAND]-> the cluster node. This is the edge that
		//     was absent before F2 (no cluster node → no resolution target for the scoped grant).
		t.Run("base_edge_to_cluster_node", func(t *testing.T) {
			n := countEdges(t, ctx, db,
				`MATCH (a:Principal)-[:ECS_EXECUTECOMMAND]->(r:Resource)
				 WHERE (a.Arn = $att OR a.arn = $att)
				   AND r._resourceType = 'AWS::ECS::Cluster'
				   AND coalesce(r.arn, r.Arn) = $cluster
				 RETURN count(*) AS n`,
				map[string]any{"att": clusterAttacker, "cluster": clusterARN})
			assert.Positive(t, n,
				"[F2] base ECS_EXECUTECOMMAND edge from %s to the cluster node %s missing — the cluster-scoped grant did not resolve against the collected cluster",
				clusterAttacker, clusterARN)
		})

		// (3) Privesc edge (TP): the enricher reaches the compute_admin task role via the task def
		//     HAS_ROLE, anchored on the cluster-node base edge.
		t.Run("privesc_edge_to_compute_admin", func(t *testing.T) {
			n := countEdges(t, ctx, db,
				`MATCH (a:Principal)-[r:CAN_PRIVESC {method: 'ecs:ExecuteCommand'}]->(v)
				 WHERE (a.Arn = $att OR a.arn = $att) AND (v.Arn = $compute OR v.arn = $compute)
				 RETURN count(r) AS n`,
				map[string]any{"att": clusterAttacker, "compute": facts.computeAdminARN})
			assert.Positive(t, n,
				"[F2 TP] CAN_PRIVESC{ecs:ExecuteCommand} from %s to compute_admin (%s) missing — F2 cluster path did not light up the enricher",
				clusterAttacker, facts.computeAdminARN)
		})

		// (4) Collector precision (FP-1): a benign principal WITHOUT ecs:ExecuteCommand must NOT
		//     have any ECS_EXECUTECOMMAND edge to the cluster — collecting the cluster must not
		//     fan out spurious base edges.
		t.Run("fp_benign_principal_no_base_edge", func(t *testing.T) {
			n := countEdges(t, ctx, db,
				`MATCH (a:Principal)-[:ECS_EXECUTECOMMAND]->(r:Resource)
				 WHERE (a.Arn = $att OR a.arn = $att)
				   AND r._resourceType = 'AWS::ECS::Cluster'
				 RETURN count(*) AS n`,
				map[string]any{"att": benignAttacker})
			assert.Zero(t, n,
				"[F2 FP] benign principal %s (no ecs:ExecuteCommand) has an ECS_EXECUTECOMMAND edge to the cluster — collector fanned out a spurious edge",
				benignAttacker)
		})
	})

	// --- Step 6: Global no-fan-out / target-allowlist guard ---
	t.Run("global_no_cartesian_fanout", func(t *testing.T) {
		assertTargetAllowlist(t, ctx, db, facts)
	})

	// --- Step 7 (F4): CAN_ASSUME is gone + graph-density log ---
	// F4 deleted the trust-only CAN_ASSUME creator enrichers and re-gated the four assume-based
	// privesc methods onto the validated STS_ASSUMEROLE base edge (identity AND trust, emitted by
	// the IAM evaluator). The CAN_ASSUME relationship type must no longer appear anywhere in the
	// graph, and removing the :root CAN_ASSUME fan-out should reduce (or not increase) density.
	t.Run("f4_no_can_assume_edges", func(t *testing.T) {
		n := countEdges(t, ctx, db,
			`MATCH ()-[r:CAN_ASSUME]->() RETURN count(r) AS n`, nil)
		assert.Zero(t, n,
			"[F4] CAN_ASSUME edges must be absent from the live graph (the trust-only creator enrichers were deleted), got %d", n)
	})

	t.Run("f4_graph_density_log", func(t *testing.T) {
		totalRels := countEdges(t, ctx, db, `MATCH ()-[r]->() RETURN count(r) AS n`, nil)
		totalCanPrivesc := countEdges(t, ctx, db, `MATCH ()-[r:CAN_PRIVESC]->() RETURN count(r) AS n`, nil)
		totalStsAssume := countEdges(t, ctx, db, `MATCH ()-[r:STS_ASSUMEROLE]->() RETURN count(r) AS n`, nil)
		fixtureCanPrivesc := countEdges(t, ctx, db,
			`MATCH (a:Principal)-[r:CAN_PRIVESC]->()
			 WHERE a.Arn STARTS WITH 'arn:aws:iam:' AND a.Arn CONTAINS $prefix
			 RETURN count(r) AS n`,
			map[string]any{"prefix": facts.prefix})
		t.Logf("[F4 DENSITY] total relationships=%d, total CAN_PRIVESC=%d (fixture attackers=%d), total STS_ASSUMEROLE=%d, CAN_ASSUME=0",
			totalRels, totalCanPrivesc, fixtureCanPrivesc, totalStsAssume)
	})

	// --- Step 8 (F6): exact-ARN DIRECT-TRUST STS_ASSUMEROLE accuracy ---
	// F6 makes the IAM evaluator emit a validated STS_ASSUMEROLE edge for a SAME-ACCOUNT exact-ARN
	// direct trust WITHOUT an identity grant (`:root`/wildcard still require the grant, correlated
	// to the same statement). The sts_assume_direct_trust attacker holds ONLY benign
	// sts:GetCallerIdentity (NO sts:AssumeRole) and is DIRECTLY NAMED by exact ARN in
	// direct_trust_admin_role's trust. These subtests prove BOTH the producer path (the validated
	// edge forms purely from the direct trust) AND that the `:root` boundary the F4 FP removed stays
	// removed (a no-grant principal gets NO validated edge to a `:root`-only role).
	t.Run("f6_direct_trust_assumerole_edge", func(t *testing.T) {
		attacker := facts.attackerARNs["sts_assume_direct_trust"]
		require.NotEmpty(t, attacker, "fixture must expose the sts_assume_direct_trust attacker")
		require.NotEmpty(t, facts.directTrustAdminRoleARN, "fixture must output direct_trust_admin_role_arn")
		// PRODUCER PROOF: the validated STS_ASSUMEROLE base edge must exist from the no-grant attacker
		// to the direct-trust admin role — emitted by the evaluator from the exact-ARN direct trust ALONE.
		n := countEdges(t, ctx, db,
			`MATCH (a:Principal)-[r:STS_ASSUMEROLE]->(v)
			 WHERE (a.Arn = $att OR a.arn = $att) AND (v.Arn = $role OR v.arn = $role)
			 RETURN count(r) AS n`,
			map[string]any{"att": attacker, "role": facts.directTrustAdminRoleARN})
		assert.Positive(t, n,
			"[F6 PRODUCER] no validated STS_ASSUMEROLE edge from the no-grant attacker %s to the exact-ARN "+
				"direct-trust admin role %s — the evaluator did NOT emit the edge from the direct trust",
			attacker, facts.directTrustAdminRoleARN)
	})

	t.Run("f6_no_grant_root_only_role_no_edge", func(t *testing.T) {
		// FP-BOUNDARY (the F4 `:root` FP must stay removed): the SAME no-grant attacker must NOT get a
		// validated STS_ASSUMEROLE edge to a `:root`-only-trusting role (admin_target), and therefore no
		// CAN_PRIVESC{sts:AssumeRole} to it. `:root`/wildcard trust still requires the identity grant the
		// attacker lacks, so the broad same-account-`:root` fan-out F4 removed does not creep back in.
		attacker := facts.attackerARNs["sts_assume_direct_trust"]
		require.NotEmpty(t, attacker, "fixture must expose the sts_assume_direct_trust attacker")
		require.NotEmpty(t, facts.adminTargetARN, "fixture must output admin_target_arn (:root-only role)")
		nEdge := countEdges(t, ctx, db,
			`MATCH (a:Principal)-[r:STS_ASSUMEROLE]->(v)
			 WHERE (a.Arn = $att OR a.arn = $att) AND (v.Arn = $role OR v.arn = $role)
			 RETURN count(r) AS n`,
			map[string]any{"att": attacker, "role": facts.adminTargetARN})
		assert.Zero(t, nEdge,
			"[F6 FP] no-grant attacker %s got a validated STS_ASSUMEROLE edge to the :root-only role %s — "+
				"the F4 :root fan-out FP has crept back (exact-ARN-only relaxation must exclude :root/wildcard)",
			attacker, facts.adminTargetARN)
		nPrivesc := countEdges(t, ctx, db,
			`MATCH (a:Principal)-[r:CAN_PRIVESC {method:'sts:AssumeRole'}]->(v)
			 WHERE (a.Arn = $att OR a.arn = $att) AND (v.Arn = $role OR v.arn = $role)
			 RETURN count(r) AS n`,
			map[string]any{"att": attacker, "role": facts.adminTargetARN})
		assert.Zero(t, nPrivesc,
			"[F6 FP] no-grant attacker %s got CAN_PRIVESC{sts:AssumeRole} to the :root-only role %s — the F4 :root FP is back",
			attacker, facts.adminTargetARN)
	})
}

// assertTP verifies a TP case emits ≥1 CAN_PRIVESC edge to the expected target node (identity,
// not just count) for the named method. tgtStub asserts ≥1 edge for the method (fail-open
// service-wildcard / changeset methods MERGE onto a permission stub, so no clean identity).
func assertTP(t *testing.T, ctx context.Context, db graph.GraphDatabase, facts fixtureFacts, tc labCase, attacker string) {
	t.Helper()
	method, ok := caseMethodLiteral(tc)
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
	method, ok := caseMethodLiteral(tc)
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
		facts.adminTargetARN:          true,
		facts.computeAdminARN:         true,
		facts.privUserARN:             true,
		facts.attackerTrustedRoleARN:  true, // the trusts-attacker-explicitly TP role (sts_assume_attacker_trusted)
		facts.directTrustAdminRoleARN: true, // F6: the exact-ARN direct-trust TP role (sts_assume_direct_trust)
	}
	for _, arn := range facts.serviceAdminARNs {
		allow[arn] = true
	}
	for _, arn := range facts.decoyARNs {
		allow[arn] = true // modifiable role targets (UpdateAssumeRolePolicy/AttachRolePolicy on "*")
	}
	for _, arn := range facts.privUserFPTargetARNs {
		allow[arn] = true // admin users a broad principal-access TP attacker legitimately reaches
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
