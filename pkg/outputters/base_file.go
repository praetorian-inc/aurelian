package outputters

import (
	"fmt"
	"path/filepath"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/utils"
)

// BaseFileOutputter provides common file handling functionality for outputters
// that need to write to files. It handles directory creation and path management.
type BaseFileOutputter struct {
	cfg        plugin.Config
	outputPath string
}

// NewBaseFileOutputter creates a new BaseFileOutputter
func NewBaseFileOutputter() *BaseFileOutputter {
	return &BaseFileOutputter{}
}

// SetConfig stores the configuration for later parameter access
func (b *BaseFileOutputter) SetConfig(cfg plugin.Config) {
	b.cfg = cfg
}

// GetArg retrieves a typed argument from the stored configuration
func (b *BaseFileOutputter) GetArg(name string, defaultValue any) any {
	if b.cfg.Args == nil {
		return defaultValue
	}
	if val, ok := b.cfg.Args[name]; ok {
		return val
	}
	return defaultValue
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
