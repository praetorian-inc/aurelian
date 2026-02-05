package plugin

import (
	"encoding/json"
	"fmt"
	"io"
)

// Formatter handles output formatting for module results
type Formatter interface {
	Format(results []Result) error
}

// JSONFormatter outputs results as JSON
type JSONFormatter struct {
	Writer io.Writer
	Pretty bool
}

// Format implements the Formatter interface for JSON output
func (f *JSONFormatter) Format(results []Result) error {
	encoder := json.NewEncoder(f.Writer)
	if f.Pretty {
		encoder.SetIndent("", "  ")
	}
	return encoder.Encode(results)
}

// ConsoleFormatter outputs results to console in a human-readable format
type ConsoleFormatter struct {
	Writer io.Writer
}

// Format implements the Formatter interface for console output
func (f *ConsoleFormatter) Format(results []Result) error {
	for _, r := range results {
		if r.Error != nil {
			fmt.Fprintf(f.Writer, "ERROR: %v\n", r.Error)
			continue
		}
		fmt.Fprintf(f.Writer, "%+v\n", r.Data)
	}
	return nil
}

// MarkdownFormatter outputs results as Markdown (stub for future implementation)
type MarkdownFormatter struct {
	Writer io.Writer
}

// Format implements the Formatter interface for Markdown output
func (f *MarkdownFormatter) Format(results []Result) error {
	// TODO: Implement markdown formatting
	fmt.Fprintf(f.Writer, "# Results\n\n")
	for i, r := range results {
		if r.Error != nil {
			fmt.Fprintf(f.Writer, "## Error %d\n\n```\n%v\n```\n\n", i+1, r.Error)
			continue
		}
		fmt.Fprintf(f.Writer, "## Result %d\n\n```json\n%+v\n```\n\n", i+1, r.Data)
	}
	return nil
}
