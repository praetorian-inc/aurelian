variable "region" {
  type    = string
  default = "us-east-1"
}

variable "external_account_id" {
  description = "A 12-digit account ID to associate as a principal, exercising AllowExternalPrincipals=true."
  type        = string
  # A well-known non-org account id placeholder; the share is created regardless
  # of whether an invitation is ever accepted, which is all the enumerator reads.
  default = "210987654321"
}
