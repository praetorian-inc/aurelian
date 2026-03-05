variable "location" {
  description = "Azure region for all resources"
  type        = string
  default     = "westeurope"
}

# ── KQL Filter Tests ──

variable "enable_tp" {
  description = "Enable public function app with no IP restrictions (TP - detected by KQL)"
  type        = bool
  default     = true
}

variable "enable_tn_private" {
  description = "Enable function app with public access disabled (TN - not detected by KQL)"
  type        = bool
  default     = true
}

variable "enable_tn_restricted" {
  description = "Enable public function app with IP restrictions (TN - not detected by KQL)"
  type        = bool
  default     = true
}

# ── Enricher-Level Tests ──

variable "enable_tp_slot" {
  description = "Enable public function app with deployment slot (enricher slot enumeration test)"
  type        = bool
  default     = true
}

variable "enable_tn_easyauth" {
  description = "Enable public function app with EasyAuth enabled (enricher compensating control test)"
  type        = bool
  default     = true
}

variable "enable_tp_anonymous" {
  description = "Enable public function app for anonymous trigger deployment (requires func CLI deploy)"
  type        = bool
  default     = true
}

variable "enable_tn_keyed" {
  description = "Enable public function app for function-key trigger deployment (requires func CLI deploy)"
  type        = bool
  default     = true
}
