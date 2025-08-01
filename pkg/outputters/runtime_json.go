package outputters

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
)

// NamedOutputData represents the structure that should be sent to the RuntimeJSONOutputter
// It contains both the data to be output and the filename to write it to
type NamedOutputData struct {
	OutputFilename string
	Data           any
}

const defaultOutfile = "out.json"

// RuntimeJSONOutputter allows specifying the output file at runtime
// rather than at initialization time
type RuntimeJSONOutputter struct {
	*chain.BaseOutputter
	indent  int
	output  []any
	outfile string
}

// NewRuntimeJSONOutputter creates a new RuntimeJSONOutputter
func NewRuntimeJSONOutputter(configs ...cfg.Config) chain.Outputter {
	j := &RuntimeJSONOutputter{}
	j.BaseOutputter = chain.NewBaseOutputter(j, configs...)
	return j
}

// Initialize sets up the outputter but doesn't open a file yet
func (j *RuntimeJSONOutputter) Initialize() error {
	// Get default output file (can be overridden at runtime)
	outfile, err := cfg.As[string](j.Arg("jsonoutfile"))
	if err != nil {
		outfile = defaultOutfile // Fallback default
	}
	j.outfile = outfile

	// Get indentation setting
	indent, err := cfg.As[int](j.Arg("indent"))
	if err != nil {
		indent = 0
	}
	j.indent = indent

	slog.Debug("initialized runtime JSON outputter", "default_file", j.outfile, "indent", j.indent)
	return nil
}

// Output stores a value in memory for later writing
func (j *RuntimeJSONOutputter) Output(val any) error {
	// Check if we received an OutputData structure
	if outputData, ok := val.(NamedOutputData); ok {
		// If filename is provided, update the output file
		if outputData.OutputFilename != "" && j.outfile == defaultOutfile {
			j.SetOutputFile(outputData.OutputFilename)
		}
		// Add the actual data to our output list
		j.output = append(j.output, outputData.Data)
	} else {
		// Handle the original case where just data is provided
		j.output = append(j.output, val)
	}
	return nil
}

// SetOutputFile allows changing the output file at runtime
func (j *RuntimeJSONOutputter) SetOutputFile(filename string) {
	j.outfile = filename
	slog.Debug("changed JSON output file", "filename", filename)
}

// Complete writes all stored outputs to the specified file
func (j *RuntimeJSONOutputter) Complete() error {
	slog.Debug("writing JSON output", "filename", j.outfile, "entries", len(j.output))

	writer, err := os.Create(j.outfile)
	if err != nil {
		return fmt.Errorf("error creating JSON file %s: %w", j.outfile, err)
	}
	defer writer.Close()

	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", strings.Repeat(" ", j.indent))

	return encoder.Encode(j.output)
}

// Params defines the parameters accepted by this outputter
func (j *RuntimeJSONOutputter) Params() []cfg.Param {
	return []cfg.Param{
		cfg.NewParam[string]("jsonoutfile", "the default file to write the JSON to (can be changed at runtime)").WithDefault(defaultOutfile),
		cfg.NewParam[int]("indent", "the number of spaces to use for the JSON indentation").WithDefault(0),
	}
}
