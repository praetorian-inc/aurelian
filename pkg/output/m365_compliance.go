package output

import "github.com/praetorian-inc/aurelian/pkg/model"

// M365ComplianceStatus represents the status of a CIS benchmark control.
type M365ComplianceStatus string

const (
	CompliancePass      M365ComplianceStatus = "PASS"
	ComplianceFail      M365ComplianceStatus = "FAIL"
	ComplianceNotTested M365ComplianceStatus = "NOT TESTED"
)

// M365ComplianceEntry represents a single CIS benchmark control result.
type M365ComplianceEntry struct {
	CISID   string               `json:"cis_id"`
	Title   string               `json:"title"`
	Level   string               `json:"level"`             // L1, L2
	Service string               `json:"service"`           // admin, defender, entra, etc.
	Status  M365ComplianceStatus `json:"status"`
	Message string               `json:"message,omitempty"` // check result message if PASS/FAIL
}

// M365ComplianceMap is the full compliance map emitted as an AurelianModel.
type M365ComplianceMap struct {
	model.BaseAurelianModel
	TenantID      string                `json:"tenant_id"`
	TenantDomain  string                `json:"tenant_domain"`
	Benchmark     string                `json:"benchmark"`       // "CIS Microsoft 365 Foundations Benchmark v6.0.0"
	TotalControls int                   `json:"total_controls"`
	Tested        int                   `json:"tested"`
	Passed        int                   `json:"passed"`
	Failed        int                   `json:"failed"`
	NotTested     int                   `json:"not_tested"`
	Entries       []M365ComplianceEntry `json:"entries"`
}
