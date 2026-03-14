package output

import (
	"fmt"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/model"
)

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

// String renders the cost summary as a formatted markdown table.
func (t *AWSCostSummary) String() string {
	if len(t.Headers) == 0 {
		return t.TableHeading
	}

	// Calculate column widths.
	widths := make([]int, len(t.Headers))
	for i, h := range t.Headers {
		widths[i] = len(h)
	}
	for _, row := range t.Rows {
		for i, cell := range row {
			if i < len(widths) && len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}

	var sb strings.Builder
	sb.WriteString(t.TableHeading)

	// Header row.
	for i, h := range t.Headers {
		if i > 0 {
			sb.WriteString(" | ")
		}
		sb.WriteString(fmt.Sprintf("%-*s", widths[i], h))
	}
	sb.WriteByte('\n')

	// Separator row.
	for i, w := range widths {
		if i > 0 {
			sb.WriteString("-|-")
		}
		sb.WriteString(strings.Repeat("-", w))
	}
	sb.WriteByte('\n')

	// Data rows.
	for _, row := range t.Rows {
		for i, cell := range row {
			if i > 0 {
				sb.WriteString(" | ")
			}
			if i < len(widths) {
				sb.WriteString(fmt.Sprintf("%-*s", widths[i], cell))
			} else {
				sb.WriteString(cell)
			}
		}
		sb.WriteByte('\n')
	}

	return sb.String()
}
