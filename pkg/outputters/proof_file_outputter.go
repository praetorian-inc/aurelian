package outputters

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// ProofFileOutputter handles model.File objects (proofs and definitions) by writing them to disk
type ProofFileOutputter struct {
	*BaseFileOutputter
	outputDirectory string
	filesWritten    int
}

// NewProofFileOutputter creates a new proof file outputter
func NewProofFileOutputter() plugin.Outputter {
	o := &ProofFileOutputter{
		BaseFileOutputter: NewBaseFileOutputter(),
	}
	return o
}

// Initialize sets up the outputter and determines the output directory
func (o *ProofFileOutputter) Initialize(cfg plugin.Config) error {
	o.SetConfig(cfg)

	// Get base output directory
	outputDir := o.GetArg("output", "aurelian-output").(string)
	o.outputDirectory = outputDir

	return nil
}

// Output handles model.File objects and writes them to disk
func (o *ProofFileOutputter) Output(v any) error {
	// Handle model.File objects
	if file, ok := v.(model.File); ok {
		return o.writeFile(file)
	}

	// Silently ignore non-File objects
	return nil
}

// writeFile writes a model.File to disk
func (o *ProofFileOutputter) writeFile(file model.File) error {
	// Construct full path - file.Name contains path like "proofs/{dns}/{name}"
	fullPath := filepath.Join(o.outputDirectory, file.Name)

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
		return fmt.Errorf("failed to create proof directory: %w", err)
	}

	// Write the file content
	if err := os.WriteFile(fullPath, file.Bytes, 0644); err != nil {
		return fmt.Errorf("failed to write proof file: %w", err)
	}

	o.filesWritten++
	slog.Debug("wrote proof file", "path", fullPath, "size", len(file.Bytes))
	return nil
}

// Complete is called when processing is done
func (o *ProofFileOutputter) Complete() error {
	if o.filesWritten > 0 {
		slog.Debug("proof file outputter complete", "files_written", o.filesWritten)
	}
	return nil
}
