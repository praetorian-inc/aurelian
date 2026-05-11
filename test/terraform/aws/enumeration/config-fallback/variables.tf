variable "region" {
  type        = string
  description = "AWS region for the fixture."
  default     = "us-east-1"
}

variable "name_prefix" {
  type        = string
  description = "Prefix applied to all named resources for uniqueness."
  default     = "aurelian-cfg-fallback"
}
