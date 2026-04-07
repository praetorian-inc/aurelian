variable "location" {
  description = "Azure region for ARM resources"
  type        = string
  default     = "eastus2"
}

variable "domain" {
  description = "Entra ID verified domain for test user UPNs (e.g. yourtenant.onmicrosoft.com)"
  type        = string
}
