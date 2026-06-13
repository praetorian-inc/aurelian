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
  )
}

# The EC2/SSM/Lambda compute exec role: target of the existing-compute HAS_ROLE methods.
output "compute_admin_arn" {
  value = aws_iam_role.compute_admin.arn
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
output "wrong_service_target_arn" {
  value = aws_iam_role.wrong_service_target.arn
}
output "nonpriv_lambda_target_arn" {
  value = aws_iam_role.nonpriv_lambda_target.arn
}

# Admin decoy that trusts ONLY a service principal (no :root, no attacker) → no CAN_ASSUME built
# → the trust-backed direct-takeover FPs (AttachRolePolicy/AssumeRole scoped to it) must not fire.
output "service_only_trust_role_arn" {
  value = aws_iam_role.service_only_trust_role.arn
}

# Admin role whose trust EXPLICITLY names the sts_assume_attacker_trusted attacker → CAN_ASSUME is
# built → sts_assume_role fires (TP). Completes the trust-mismatch matrix's trusts-attacker cell.
output "attacker_trusted_role_arn" {
  value = aws_iam_role.attacker_trusted_role.arn
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
  value = { for k, u in aws_iam_user.full_attacker : k => u.arn }
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
      aws_iam_role.wrong_service_target.arn,
      aws_iam_role.nonpriv_lambda_target.arn,
      aws_iam_role.service_only_trust_role.arn,
      aws_iam_role.attacker_trusted_role.arn,
      aws_iam_role.cognito_admin.arn,
      aws_lambda_function.compute.arn,
      aws_instance.compute.arn,
    ],
    [for r in aws_iam_role.service_admin : r.arn],
    [for u in aws_iam_user.attacker : u.arn],
    [for u in aws_iam_user.full_attacker : u.arn],
    [for r in aws_iam_role.full_service_admin : r.arn],
  )
}
