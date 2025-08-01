package types

import "strings"

type OutputProvider interface {
	Write(result Result) error
}

type OutputProviders []func(options []*Option) OutputProvider

type MarkdownTable struct {
	TableHeading string
	Headers      []string
	Rows         [][]string
}

func (t *MarkdownTable) ToMarkdown() string {
	var builder strings.Builder

	if t.TableHeading != "" {
		builder.WriteString(t.TableHeading)
		builder.WriteString("\n\n")
	}

	// Write headers
	builder.WriteString("|")
	for _, header := range t.Headers {
		builder.WriteString(" ")
		builder.WriteString(header)
		builder.WriteString(" |")
	}
	builder.WriteString("\n")

	// Write separator
	builder.WriteString("|")
	for range t.Headers {
		builder.WriteString("---|")
	}
	builder.WriteString("\n")

	// Write rows
	for _, row := range t.Rows {
		builder.WriteString("|")
		for _, cell := range row {
			builder.WriteString(" ")
			builder.WriteString(cell)
			builder.WriteString(" |")
		}
		builder.WriteString("\n")
	}

	return builder.String()
}
