package outputters

import (
	"fmt"
	"path/filepath"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/utils"
)

// BaseFileOutputter provides common file handling functionality for outputters
// that need to write to files. It handles directory creation and path management.
type BaseFileOutputter struct {
	*chain.BaseOutputter
	outputPath string
}

// NewBaseFileOutputter creates a new BaseFileOutputter
func NewBaseFileOutputter(outputter chain.Outputter, configs ...cfg.Config) *BaseFileOutputter {
	return &BaseFileOutputter{
		BaseOutputter: chain.NewBaseOutputter(outputter, configs...),
	}
}

// EnsureOutputPath creates the output path and ensures all necessary directories exist
func (b *BaseFileOutputter) EnsureOutputPath(filePath string) error {
	// Store the output path
	b.outputPath = filePath
	
	// Ensure the file's directory exists
	if err := utils.EnsureFileDirectory(filePath); err != nil {
		return fmt.Errorf("failed to create directory for output file %s: %w", filePath, err)
	}
	
	return nil
}

// GetOutputPath returns the current output path
func (b *BaseFileOutputter) GetOutputPath() string {
	return b.outputPath
}

// GetOutputDir returns the directory portion of the output path
func (b *BaseFileOutputter) GetOutputDir() string {
	if b.outputPath == "" {
		return ""
	}
	return filepath.Dir(b.outputPath)
}

// SetOutputPath sets a new output path and ensures its directory exists
func (b *BaseFileOutputter) SetOutputPath(filePath string) error {
	return b.EnsureOutputPath(filePath)
}