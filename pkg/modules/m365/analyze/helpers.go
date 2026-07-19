package analyze

import (
	m365templates "github.com/praetorian-inc/aurelian/pkg/templates/m365"
)

// M365CheckContext is the structured context emitted with each AurelianRisk.
type M365CheckContext struct {
	CISID        string         `json:"cis_id"`
	CISTitle     string         `json:"cis_title"`
	Service      string         `json:"service"`
	Level        string         `json:"level"`
	Profile      string         `json:"profile"`
	Execution    string         `json:"execution"`
	TenantID     string         `json:"tenant_id"`
	TenantDomain string         `json:"tenant_domain"`
	Evidence     map[string]any `json:"evidence,omitempty"`
	Message      string         `json:"message"`
	Remediation  string         `json:"remediation"`
	Rationale    string         `json:"rationale"`
	References   []string       `json:"references,omitempty"`
	Guard        m365templates.GuardMeta `json:"guard"`
}
