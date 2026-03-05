variable "location" {
  description = "Azure region for all resources"
  type        = string
  default     = "eastus"
}

variable "enable_tp_name" {
  description = "Enable storage account with Cloud Shell naming pattern (TP - detected)"
  type        = bool
  default     = true
}

variable "enable_tp_tag" {
  description = "Enable storage account with Cloud Shell tag (TP - detected)"
  type        = bool
  default     = true
}

variable "enable_tn" {
  description = "Enable regular storage account (TN - not detected)"
  type        = bool
  default     = true
}
