variable "location" {
  description = "Azure region for all resources"
  type        = string
  default     = "eastus"
}

variable "enable_tp" {
  description = "Enable custom role with dangerous permissions (TP - detected)"
  type        = bool
  default     = true
}

variable "enable_tn" {
  description = "Enable custom role with safe permissions (TN - not detected)"
  type        = bool
  default     = true
}
