variable "location" {
  description = "Azure region for all resources"
  type        = string
  default     = "eastus"
}

variable "enable_aks_no_rbac" {
  description = "Enable AKS cluster without RBAC (TP) via az CLI (~$0.08/hr). Requires az CLI installed."
  type        = bool
  default     = true
}

variable "enable_aks_rbac" {
  description = "Enable AKS cluster with RBAC enabled (TN) (~$0.08/hr)"
  type        = bool
  default     = true
}
