# =============================================================================
# --full tier (AURELIAN_E2E_FULL=1 → TF_VAR_enable_full=true).
#
# The expensive / long-provisioning backing compute for the EMR, EMR-Serverless,
# GameLift, ImageBuilder, Braket, Omics and KinesisAnalytics privesc paths is gated
# behind var.enable_full (for_each over an empty map when off), so the default suite never
# provisions it (keeps the default run fast AND keeps the fixture content-hash stable when
# the flag is off).
#
# THIS PASS authors only the cheap, always-safe pieces of the full tier: the per-service
# admin TARGET roles (IAM-only, no runtime cost) and the attacker IAM users + policies,
# all flag-gated. The actual heavyweight backing compute (EMR clusters, GameLift fleets,
# ImageBuilder pipelines, Braket/Omics/KinesisAnalytics applications) is DEFERRED to the
# next pass — those resources take 5-20 min to provision and need a longer runner timeout;
# they will be added here under the same flag gate. The Go harness logs every full-tier
# case as skipped when the flag is off, so coverage stays honest.
# =============================================================================

locals {
  # Per-service admin target roles for the full-tier PassRole methods. Same shape as
  # local.service_trust_principals but only provisioned with the flag on.
  full_service_trust_principals = {
    emr              = "elasticmapreduce.amazonaws.com"
    emrserverless    = "emr-serverless.amazonaws.com"
    gamelift         = "gamelift.amazonaws.com"
    imagebuilder     = "ec2.amazonaws.com"
    braket           = "braket.amazonaws.com"
    omics            = "omics.amazonaws.com"
    kinesisanalytics = "kinesisanalytics.amazonaws.com"
  }

  # Full-tier attacker users: TP (PassRole + the create action) per expensive technique,
  # plus the missing-permission FP variants the legacy suite carried.
  full_attackers = {
    emr_run_job_flow           = [{ actions = ["iam:PassRole", "elasticmapreduce:RunJobFlow"], resources = ["*"] }]
    emr_serverless             = [{ actions = ["iam:PassRole", "emr-serverless:CreateApplication"], resources = ["*"] }]
    emr_serverless_startjobrun = [{ actions = ["iam:PassRole", "emr-serverless:CreateApplication", "emr-serverless:StartJobRun"], resources = ["*"] }]
    gamelift_create_fleet      = [{ actions = ["iam:PassRole", "gamelift:CreateFleet"], resources = ["*"] }]
    gamelift_build_fleet       = [{ actions = ["iam:PassRole", "gamelift:CreateBuild", "gamelift:CreateFleet"], resources = ["*"] }]
    imagebuilder_pipeline      = [{ actions = ["iam:PassRole", "imagebuilder:CreateInfrastructureConfiguration"], resources = ["*"] }]
    imagebuilder_createimage   = [{ actions = ["iam:PassRole", "imagebuilder:CreateInfrastructureConfiguration", "imagebuilder:CreateImage"], resources = ["*"] }]
    braket_create_job          = [{ actions = ["iam:PassRole", "braket:CreateJob"], resources = ["*"] }]
    omics_create_workflow      = [{ actions = ["iam:PassRole", "omics:CreateWorkflow"], resources = ["*"] }]
    omics_startrun             = [{ actions = ["iam:PassRole", "omics:CreateWorkflow", "omics:StartRun"], resources = ["*"] }]
    kinesisanalytics           = [{ actions = ["iam:PassRole", "kinesisanalytics:CreateApplication"], resources = ["*"] }]
    kinesisanalytics_startapp  = [{ actions = ["iam:PassRole", "kinesisanalytics:CreateApplication", "kinesisanalytics:StartApplication"], resources = ["*"] }]

    # FP missing-permission variants (legacy suite parity).
    fp_emr_runjobflow_no_passrole = [{ actions = ["elasticmapreduce:RunJobFlow"], resources = ["*"] }]
    fp_emrserverless_no_start     = [{ actions = ["iam:PassRole", "emr-serverless:CreateApplication"], resources = ["*"] }]
  }
}

resource "aws_iam_role" "full_service_admin" {
  for_each = var.enable_full ? local.full_service_trust_principals : {}
  name     = "${local.prefix}-fulladmin-${each.key}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = each.value }
    }]
  })
  tags = local.tags
}
resource "aws_iam_role_policy_attachment" "full_service_admin" {
  for_each   = var.enable_full ? local.full_service_trust_principals : {}
  role       = aws_iam_role.full_service_admin[each.key].name
  policy_arn = local.admin_policy
}

resource "aws_iam_user" "full_attacker" {
  for_each = var.enable_full ? local.full_attackers : {}
  name     = "${local.prefix}-full-${replace(each.key, "_", "-")}"
  tags     = merge(local.tags, { Lab = each.key, Tier = "full" })
}
resource "aws_iam_user_policy" "full_attacker" {
  for_each = var.enable_full ? local.full_attackers : {}
  name     = "${local.prefix}-full-${replace(each.key, "_", "-")}"
  user     = aws_iam_user.full_attacker[each.key].name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [for s in each.value : {
      Effect   = "Allow"
      Action   = s.actions
      Resource = s.resources
    }]
  })
}
