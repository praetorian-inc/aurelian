variable "location" {
  description = "Azure region for networking and resource group"
  type        = string
  default     = "eastus"
}

variable "openai_location" {
  description = "Azure region for OpenAI resources (limited availability)"
  type        = string
  default     = "eastus"
}

variable "enable_private_endpoint" {
  description = "Enable private endpoint test resources (~$0.01/hr for VNet + PE)"
  type        = bool
  default     = true
}
