variable "location" {
  description = "Azure region for all resources"
  type        = string
  default     = "eastus"
}

variable "enable_aks" {
  description = "Enable AKS cluster test resources (~$0.08/hr per cluster, quota restrictions may apply)"
  type        = bool
  default     = true
}
