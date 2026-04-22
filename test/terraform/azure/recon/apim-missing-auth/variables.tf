variable "location" {
  description = "Azure region for test resources"
  type        = string
  default     = "westus2"
}

variable "subscription_id" {
  description = "Target Azure subscription ID"
  type        = string
}
