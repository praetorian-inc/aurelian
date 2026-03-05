variable "location" {
  description = "Azure region for all resources"
  type        = string
  default     = "eastus"
}

variable "enable_kusto" {
  description = "Enable Kusto cluster TP (~$0.25/hr, takes ~15 min to provision)"
  type        = bool
  default     = true
}

variable "enable_kusto_tn" {
  description = "Enable Kusto cluster TN with restricted tenants (~$0.25/hr, takes ~15 min to provision)"
  type        = bool
  default     = false
}
