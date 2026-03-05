variable "location" {
  description = "Azure region for all resources"
  type        = string
  default     = "westus2"
}

# ============================================================================
# TIER TOGGLES - Enable/disable groups of resources
# ============================================================================

variable "enable_tier1" {
  description = "Tier 1: MySQL + PostgreSQL Flexible Servers (~$0.80/hr)"
  type        = bool
  default     = true
}

variable "enable_tier2" {
  description = "Tier 2: Cognitive Services, Search, Function Apps (~$0.01/hr)"
  type        = bool
  default     = true
}

variable "enable_tier3" {
  description = "Tier 3: IoT Hub, Event Grid Topics, Notification Hubs (~$0.01/hr)"
  type        = bool
  default     = true
}

variable "enable_tier4a" {
  description = "Tier 4A: App Config, Data Explorer, Container Instances, Databricks (~$0.003/hr). Note: Data Explorer takes ~15 min to provision."
  type        = bool
  default     = true
}

variable "enable_tier4b" {
  description = "Tier 4B: Synapse Analytics, ML Workspace (~$0.09/hr). Has Key Vault with soft-delete."
  type        = bool
  default     = true
}

variable "enable_tier4c" {
  description = "Tier 4C: Container Apps, Logic Apps, Application Gateway (~$0.26/hr). App Gateway is expensive."
  type        = bool
  default     = true
}

variable "enable_tier5a" {
  description = "Tier 5A: Storage, Key Vault, App Service, Data Factory, Log Analytics, Container Registry (~$0.01/hr)"
  type        = bool
  default     = true
}

variable "enable_tier5b" {
  description = "Tier 5B: SQL Server, Cosmos DB, Service Bus, Event Hub, Redis Cache, ACR Anonymous Pull (~$0.07/hr)"
  type        = bool
  default     = true
}

variable "enable_tier5c" {
  description = "Tier 5C: AKS, API Management, Load Balancer, Virtual Machine (~$0.08/hr). AKS/VM may have quota restrictions."
  type        = bool
  default     = true
}
