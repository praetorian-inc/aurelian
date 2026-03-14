package output

import "github.com/praetorian-inc/aurelian/pkg/model"

// AWSCostSummary represents a Cost Explorer breakdown formatted as a markdown table,
// matching Nebula's MarkdownTable output structure.
type AWSCostSummary struct {
	model.BaseAurelianModel

	// TableHeading is a markdown heading displayed above the table.
	TableHeading string `json:"TableHeading"`

	// Headers are the column names: ["Service", region1, region2, ..., "Total Cost"].
	Headers []string `json:"Headers"`

	// Rows contains one slice per service, plus a final TOTAL row.
	// Each row has len(Headers) entries: service name, per-region cost strings, and row total.
	Rows [][]string `json:"Rows"`
}
