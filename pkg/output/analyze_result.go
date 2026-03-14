package output

import (
	"encoding/json"

	"github.com/praetorian-inc/aurelian/pkg/model"
)

// AnalyzeResult represents the output of an analyze utility module.
// These modules perform lookups and transformations (IP range checks,
// account ID lookups, action expansion) rather than producing resources
// or security findings.
type AnalyzeResult struct {
	model.BaseAurelianModel
	Module  string          `json:"module"`
	Input   string          `json:"input"`
	Results json.RawMessage `json:"results"`
}
