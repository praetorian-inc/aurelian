package types

import (
	"fmt"
	"strings"
)

type OutputProvider interface {
	Write(result Result) error
}

type OutputProviders []func(options []*Option) OutputProvider

type MarkdownTable struct {
	TableHeading string
	Headers      []string
	Rows         [][]string
}

// ToString converts the MarkdownTable to a markdown string
func (t MarkdownTable) ToString() string {
	var result strings.Builder
	
	// Write table heading if exists
	if t.TableHeading != "" {
		result.WriteString("# " + t.TableHeading + "\n\n")
	}
	
	if len(t.Headers) == 0 {
		return result.String()
	}

	// Dynamically determine column width
	colWidths := make([]int, len(t.Headers))
	for i, header := range t.Headers {
		colWidths[i] = len(header)
	}
	for _, row := range t.Rows {
		for i, cell := range row {
			if i < len(colWidths) && len(cell) > colWidths[i] {
				colWidths[i] = len(cell)
			}
		}
	}

	// Write header
	headerRow := "|"
	dividerRow := "|"
	for i, header := range t.Headers {
		formatter := fmt.Sprintf(" %%-%ds |", colWidths[i])
		headerRow += fmt.Sprintf(formatter, header)
		dividerRow += fmt.Sprintf(" %s |", strings.Repeat("-", colWidths[i]))
	}
	headerRow += "\n"
	dividerRow += "\n"
	result.WriteString(headerRow)
	result.WriteString(dividerRow)

	// Write rows
	for _, row := range t.Rows {
		rowText := "|"
		for i, cell := range row {
			if i < len(colWidths) {
				formatter := fmt.Sprintf(" %%-%ds |", colWidths[i])
				rowText += fmt.Sprintf(formatter, cell)
			}
		}
		rowText += "\n"
		result.WriteString(rowText)
	}
	
	return result.String()
}
