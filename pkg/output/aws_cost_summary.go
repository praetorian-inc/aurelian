package output

import (
	"fmt"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/model"
)

type AWSCostSummary struct {
	model.BaseAurelianModel
	TableHeading string     `json:"TableHeading"`
	Headers      []string   `json:"Headers"`
	Rows         [][]string `json:"Rows"`
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
		fmt.Fprintf(&sb, "%-*s", widths[i], h)
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
				fmt.Fprintf(&sb, "%-*s", widths[i], cell)
			} else {
				sb.WriteString(cell)
			}
		}
		sb.WriteByte('\n')
	}

	return sb.String()
}
