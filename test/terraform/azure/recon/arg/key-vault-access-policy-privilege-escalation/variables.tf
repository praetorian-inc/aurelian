variable "location" {
  description = "Azure region for all resources"
  type        = string
  default     = "eastus"
}

variable "enable_tp" {
  description = "Enable Key Vault with access policies (TP - detected)"
  type        = bool
  default     = true
}

variable "enable_tn" {
  description = "Enable Key Vault with RBAC authorization (TN - not detected)"
  type        = bool
  default     = true
}
