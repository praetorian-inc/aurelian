output "prefix" {
  value = local.prefix
}

output "account_id" {
  value = local.account_id
}

# --- Shared target identities (the nodes CAN_PRIVESC edges must terminate at) ---

# :root-trusted admin role: target of the trust-backed direct-takeover methods
# (sts_assume_role, iam_put_role_policy, iam_attach_role_policy, passrole_modify_policy,
# iam_update_assume_role_policy, update_assume_role_passrole_service).
output "admin_target_arn" {
  value = aws_iam_role.admin_target.arn
}

# Per-service admin target roles: target of the new-passrole methods. Keyed by the
# local.service_trust_principals key (ec2, lambda, glue, …). The cognito identity-pool
# admin role is broken out of the service_admin for_each (it carries a Federated trust,
# not a Service trust) but is the cognito_set_pool_roles new-passrole TP target, so it is
# merged in under the "cognito" key the labCase resolves.
output "service_admin_arns" {
  value = merge(
    { for k, r in aws_iam_role.service_admin : k => r.arn },
    { cognito = aws_iam_role.cognito_admin.arn },
    # Branch-coverage TP targets resolved by svcKey in the labCase table:
    #   ssm_managed    -> the ec2-trusting + AmazonSSMManagedInstanceCore admin role
    #   cognito_unauth -> the role bound to the unauthenticated-enabled identity pool
    { ssm_managed = aws_iam_role.ssm_managed_admin.arn },
    { cognito_unauth = aws_iam_role.cognito_unauth_admin.arn },
    # The auth-only-pool admin role. Under the account-scoped unauth-relax (the enricher only
    # requires an unauth-enabled pool to EXIST in the account, not a pre-bound pool->victim
    # HAS_ROLE), a PassRole+SetIdentityPoolRoles attacker can bind this cognito-trusting admin
    # role to the EXISTING unauth pool's unauth slot, so it is a legitimate escalation target.
    { cognito_authonly = aws_iam_role.cognito_authonly_admin.arn },
  )
}

# The EC2/SSM/Lambda compute exec role: target of the existing-compute HAS_ROLE methods.
output "compute_admin_arn" {
  value = aws_iam_role.compute_admin.arn
}

# --- Branch-coverage targets / real backing resources ---

# The ec2-trusting + AmazonSSMManagedInstanceCore admin role (ssm-capable via the managed
# policy, NOT ssm trust). Target of ssm_managed_send_command / ssm_managed_start_session.
output "ssm_managed_admin_arn" {
  value = aws_iam_role.ssm_managed_admin.arn
}
# The real ec2 instance running the ssm_managed_admin role (collected by the EC2-instance
# enumerator -> (instance)-[:HAS_ROLE]->(ssm_managed_admin)).
output "ssm_managed_instance_arn" {
  value = aws_instance.ssm_managed.arn
}

# The role bound to the UNAUTHENTICATED-enabled identity pool (cognito_unauth_pool TP target).
output "cognito_unauth_admin_arn" {
  value = aws_iam_role.cognito_unauth_admin.arn
}
output "cognito_unauth_pool_id" {
  value = aws_cognito_identity_pool.unauth.id
}
# The role bound to the AUTH-ONLY pool. An admin role broad-resource methods can reach,
# so it belongs in the no-fan-out allowlist (in facts.decoyARNs in the Go harness).
output "cognito_authonly_admin_arn" {
  value = aws_iam_role.cognito_authonly_admin.arn
}
output "cognito_authonly_pool_id" {
  value = aws_cognito_identity_pool.authonly.id
}

# The existing launch template referencing the compute_admin instance profile
# (real_path/launch_template asserts (LaunchTemplate)-[:HAS_ROLE]->(compute_admin)).
output "launch_template_id" {
  value = aws_launch_template.existing.id
}

# --- Full-tier real backing resources (only present when var.enable_full) ---
# A real App Runner service whose instance role is the apprunner-trusting admin role.
output "apprunner_service_arn" {
  value = var.enable_full ? aws_apprunner_service.existing[0].arn : ""
}
output "apprunner_instance_role_arn" {
  value = var.enable_full ? aws_iam_role.apprunner_instance[0].arn : ""
}
# A real SageMaker notebook instance running the compute_admin role.
output "sagemaker_notebook_name" {
  value = var.enable_full ? aws_sagemaker_notebook_instance.existing[0].name : ""
}
output "sagemaker_notebook_role_arn" {
  value = var.enable_full ? aws_iam_role.compute_admin.arn : ""
}

# The Federated-trust cognito identity-pool admin role. Not a new-passrole TP target (the
# cognito TP is a frozen-query known gap — see privesc_pathfinding_test.go), but it IS an
# admin role broad-resource methods (iam_update_assume_role_policy etc.) can legitimately
# reach, so it belongs in the no-fan-out allowlist.
output "cognito_admin_arn" {
  value = aws_iam_role.cognito_admin.arn
}

# Privileged user: target of iam_create_access_key / iam_create_login_profile /
# iam_update_login_profile.
output "priv_user_arn" {
  value = aws_iam_user.priv_user.arn
}

# Non-privileged user: the target-not-privileged FP target.
output "nonpriv_user_arn" {
  value = aws_iam_user.nonpriv_user.arn
}

# Privileged user with NO console login profile: the iam_update_login_profile FP target
# (collector → HasLoginProfile=false → suppress).
output "noprofile_user_arn" {
  value = aws_iam_user.noprofile_user.arn
}

# Privileged user already holding 2 active access keys: the iam_create_access_key FP target
# (collector → AccessKeyCount=2 → suppress).
output "twokey_user_arn" {
  value = aws_iam_user.twokey_user.arn
}

# Admin group: target of iam_add_user_to_group (joined for self-escalation).
output "admin_group_arn" {
  value = aws_iam_group.admin_group.arn
}

# Decoy roles backing the trust-mismatch / target-not-privileged FP categories.
output "trust_mismatch_target_arn" {
  value = aws_iam_role.trust_mismatch_target.arn
}

# The benign-service-trusted ROLE named in trust_mismatch_target's trust. No attacker can assume it
# (its own trust is ec2.amazonaws.com only), so it never receives an STS_ASSUMEROLE edge. Being
# _is_privileged with a non-empty service trust, it does receive the broad role-fan-out CAN_PRIVESC
# edges that hit every modifiable/privileged role — iam_update_assume_role_policy (medium),
# passrole_modify_policy (high), update_assume_role_passrole_service (medium) — the same edge classes
# already accepted for the sibling decoy roles, so it belongs in the no-fan-out decoyARNs allowlist.
output "trust_mismatch_decoy_arn" {
  value = aws_iam_role.trust_mismatch_decoy.arn
}
output "wrong_service_target_arn" {
  value = aws_iam_role.wrong_service_target.arn
}
output "nonpriv_lambda_target_arn" {
  value = aws_iam_role.nonpriv_lambda_target.arn
}

# Admin decoy that trusts ONLY a service principal (no :root, no attacker) → no attacker gets an
# STS_ASSUMEROLE edge to it → the trust-backed direct-takeover FPs (AttachRolePolicy/AssumeRole
# scoped to it) must not fire.
output "service_only_trust_role_arn" {
  value = aws_iam_role.service_only_trust_role.arn
}

# Admin role whose trust EXPLICITLY names the sts_assume_attacker_trusted attacker → that attacker,
# holding sts:AssumeRole, gets a validated STS_ASSUMEROLE edge → sts_assume_role fires (TP).
# Completes the trust-mismatch matrix's trusts-attacker cell.
output "attacker_trusted_role_arn" {
  value = aws_iam_role.attacker_trusted_role.arn
}

# F6: the no-grant attacker that is DIRECTLY NAMED in direct_trust_admin_role's trust policy. With
# NO sts:AssumeRole identity grant, the validated STS_ASSUMEROLE edge forms purely from the exact-ARN
# direct trust → sts_assume_role fires (TP) to direct_trust_admin_role.
output "sts_assume_direct_trust_attacker_arn" {
  value = aws_iam_user.attacker["sts_assume_direct_trust"].arn
}

# F6: the admin role whose trust DIRECTLY names the sts_assume_direct_trust attacker's exact ARN.
# The CAN_PRIVESC{sts:AssumeRole} target — add to the no-fan-out allowlist in the Go harness.
output "direct_trust_admin_role_arn" {
  value = aws_iam_role.direct_trust_admin_role.arn
}

# Customer-managed policy ARNs for the policy-version methods. These must be seeded as RICH nodes
# (carrying policy_version_count from the GAAD PolicyVersionList) — NOT bare relationship-endpoint
# stubs — so the version-count guards read a real signal. custom has 2 versions (>1 → the
# iam_set_default_policy_version TP and iam_create_policy_version TP fire); single_ver has 1 version
# (=1 → the fp_setdefaultversion_single_version G2 FP is suppressed). They are added to all_arns so
# the harness seeds them via NodeFromAWSIAMResource. Without this they fall back to the fail-open
# default (2 → >1), which would let the single-version FP FIRE — a false positive.
output "custom_policy_arn" {
  value = aws_iam_policy.custom.arn
}
output "single_ver_policy_arn" {
  value = aws_iam_policy.single_ver.arn
}

# --- Real common-tier compute (backing the HAS_ROLE methods on real CloudControl data) ---
output "lambda_function_arn" {
  value = aws_lambda_function.compute.arn
}
output "ec2_instance_arn" {
  value = aws_instance.compute.arn
}
output "ec2_instance_profile_name" {
  value = aws_iam_instance_profile.compute_admin.name
}

# The instance profile attached to the ec2-trusting svcadmin role: its presence is what makes
# the EC2-family new-passrole guards (InstanceProfileList CONTAINS 'arn:aws:iam') fire.
output "svcadmin_ec2_instance_profile_name" {
  value = aws_iam_instance_profile.svcadmin_ec2.name
}

# --- Phase-2a real backing service resources (collected by recon → resource_service_role
#     HAS_ROLE → privileged role; replace the synthetic stand-ins). The Go harness uses these
#     real ARNs to assert the REAL :Resource node exists (real-account ARN, not the synthetic
#     000000000000 placeholder) and that (Resource)-[:HAS_ROLE]->(role) was built. ---
output "cfn_stack_id" {
  value = aws_cloudformation_stack.compute.id
}
output "cfn_stackset_id" {
  value = aws_cloudformation_stack_set.compute.stack_set_id
}
output "batch_jobdef_arn" {
  value = aws_batch_job_definition.compute.arn
}
output "ecs_taskdef_arn" {
  value = aws_ecs_task_definition.compute.arn
}

# F2 (ecs-006): the ECS cluster the ECSClusterEnumerator collects as an AWS::ECS::Cluster node.
# The cluster-scoped ecs:ExecuteCommand attacker resolves its grant against this ARN, so the base
# ECS_EXECUTECOMMAND edge forms to this node (the gap F2 closes). Added to all_arns so the harness
# keeps the cluster node and the base edge when bounding the seeded graph.
output "ecs_cluster_arn" {
  value = aws_ecs_cluster.exec.arn
}
output "sfn_state_machine_arn" {
  value = aws_sfn_state_machine.compute.arn
}
output "glue_job_name" {
  value = aws_glue_job.compute.name
}
output "codebuild_project_arn" {
  value = aws_codebuild_project.compute.arn
}

# --- Attacker principals (TP + FP), keyed by local.attackers key ---
# Map output → expected verdict/target is encoded in the Go case table
# (privesc_pathfinding_test.go), keyed by the same map key.
output "attacker_arns" {
  value = { for k, u in aws_iam_user.attacker : k => u.arn }
}

# --- Full-tier principals (empty unless var.enable_full) ---
output "full_attacker_arns" {
  value = merge(
    { for k, u in aws_iam_user.full_attacker : k => u.arn },
    { for k, u in aws_iam_user.full_attacker_new : k => u.arn },
  )
}
output "full_service_admin_arns" {
  value = { for k, r in aws_iam_role.full_service_admin : k => r.arn }
}

# Every fixture ARN, for relationship filtering in the harness.
output "all_arns" {
  value = concat(
    [
      aws_iam_role.admin_target.arn,
      aws_iam_role.compute_admin.arn,
      aws_iam_user.priv_user.arn,
      aws_iam_user.nonpriv_user.arn,
      aws_iam_user.noprofile_user.arn,
      aws_iam_user.twokey_user.arn,
      aws_iam_group.admin_group.arn,
      aws_iam_group.member_group.arn,
      aws_iam_role.trust_mismatch_target.arn,
      aws_iam_role.trust_mismatch_decoy.arn,
      aws_iam_role.wrong_service_target.arn,
      aws_iam_role.nonpriv_lambda_target.arn,
      aws_iam_role.service_only_trust_role.arn,
      aws_iam_role.attacker_trusted_role.arn,
      aws_iam_role.direct_trust_admin_role.arn,
      aws_iam_role.cognito_admin.arn,
      aws_iam_policy.custom.arn,
      aws_iam_policy.single_ver.arn,
      aws_lambda_function.compute.arn,
      aws_instance.compute.arn,
      # Branch-coverage targets / real backing resources.
      aws_iam_role.ssm_managed_admin.arn,
      aws_instance.ssm_managed.arn,
      aws_iam_role.cognito_unauth_admin.arn,
      aws_iam_role.cognito_authonly_admin.arn,
      aws_launch_template.existing.arn,
      # F2 (ecs-006): the collected ECS cluster — kept so the base ECS_EXECUTECOMMAND edge to the
      # cluster node (whose endpoint is this ARN) survives the harness's fixtureARNs relationship filter.
      aws_ecs_cluster.exec.arn,
    ],
    [for r in aws_iam_role.service_admin : r.arn],
    [for u in aws_iam_user.attacker : u.arn],
    [for u in aws_iam_user.full_attacker : u.arn],
    [for u in aws_iam_user.full_attacker_new : u.arn],
    [for r in aws_iam_role.full_service_admin : r.arn],
    var.enable_full ? [aws_iam_role.apprunner_instance[0].arn] : [],
  )
}
