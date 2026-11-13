variable "region" {
  description = "GCP region for test resources"
  type        = string
  default     = "us-central1"
}

# Case 9 (ENG-8964): a SECOND GCP project that holds the delegated child zone.
# Supply it with TF_VAR_secondary_project_id. When empty, no case-9 resource is
# provisioned and the case-9 subtest skips; the rest of the fixture is unaffected.
variable "secondary_project_id" {
  description = "Second GCP project ID used for the cross-project NS delegation case (empty disables that case)"
  type        = string
  default     = ""
}

# Case 12 (ENG-8964 defect 2): filler Cloud DNS zones that push the delegated
# child zone past the first page of dns.managedZones.list (default page size
# 100). Supply it with TF_VAR_filler_zone_count. The default of 0 provisions
# nothing and the case-12 subtest skips; read the cost warning next to the
# case-12 resources in main.tf before raising it.
variable "filler_zone_count" {
  description = "Filler Cloud DNS zones used to push the paged delegation past the first managedZones.list page (0 disables the pagination case)"
  type        = number
  default     = 0

  validation {
    condition     = var.filler_zone_count == 0 || var.filler_zone_count >= 101
    error_message = "filler_zone_count must be 0 (disabled) or at least 101, so the delegated zone lands past the first managedZones.list page."
  }
}
