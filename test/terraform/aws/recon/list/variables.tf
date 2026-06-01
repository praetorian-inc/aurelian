variable "region" {
  description = "Primary AWS region for test resources"
  default     = "us-east-2"
}

variable "secondary_region" {
  description = "Secondary AWS region for multi-region test resources"
  default     = "us-east-1"
}

variable "tertiary_region" {
  description = "Tertiary AWS region for multi-region test resources"
  default     = "us-west-2"
}
