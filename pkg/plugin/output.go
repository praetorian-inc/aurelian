package plugin

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/praetorian-inc/aurelian/pkg/model"
)

// Formatter handles output formatting for module results
type Formatter interface {
	Format(results []model.AurelianModel) error
}

// JSONFormatter outputs results as JSON
type JSONFormatter struct {
	Writer io.Writer
	Pretty bool
}

// Format implements the Formatter interface for JSON output
func (f *JSONFormatter) Format(results []model.AurelianModel) error {
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
func (f *ConsoleFormatter) Format(results []model.AurelianModel) error {
	for _, r := range results {
		_, _ = fmt.Fprintf(f.Writer, "%+v\n", r)
	}
	return nil
}
