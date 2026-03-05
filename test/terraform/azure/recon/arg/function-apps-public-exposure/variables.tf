variable "location" {
  description = "Azure region for all resources"
  type        = string
  default     = "westus2"
}

variable "enable_private_endpoint" {
  description = "Enable private endpoint TN (requires Premium plan EP1 ~$0.17/hr + PE ~$0.01/hr)"
  type        = bool
  default     = false
}
