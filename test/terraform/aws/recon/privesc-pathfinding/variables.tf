variable "region" {
  description = "AWS region to deploy test resources"
  default     = "us-east-2"
}

# enable_full gates the expensive / long-provisioning backing compute used by the
# --full e2e tier (EMR, EMR-Serverless, GameLift, ImageBuilder, Braket, Omics,
# KinesisAnalytics). It defaults to false so the standard suite stays fast and the
# fixture content-hash is stable across default runs. The Go harness sets
# TF_VAR_enable_full=true (inherited by terraform-exec) only when AURELIAN_E2E_FULL=1.
variable "enable_full" {
  description = "Provision expensive --full-tier backing compute resources"
  type        = bool
  default     = false
}
