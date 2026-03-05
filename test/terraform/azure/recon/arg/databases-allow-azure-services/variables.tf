variable "location" {
  description = "Azure region for all resources"
  type        = string
  default     = "eastus"
}

variable "enable_postgresql" {
  description = "Enable PostgreSQL Flexible Server test resources (~$0.40/hr)"
  type        = bool
  default     = true
}

variable "enable_mysql" {
  description = "Enable MySQL Flexible Server test resources (~$0.40/hr)"
  type        = bool
  default     = true
}

variable "enable_synapse" {
  description = "Enable Synapse Workspace test resources (~$0.05/hr serverless)"
  type        = bool
  default     = true
}
