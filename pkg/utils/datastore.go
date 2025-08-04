package utils

import (
	"fmt"
	"path/filepath"
)

// DatastoreHandler provides common functionality for managing datastore files
// It handles path construction and directory creation for datastore operations
type DatastoreHandler struct {
	outputDir     string
	datastoreName string
	datastorePath string
}

// NewDatastoreHandler creates a new DatastoreHandler
func NewDatastoreHandler(outputDir, datastoreName string) *DatastoreHandler {
	return &DatastoreHandler{
		outputDir:     outputDir,
		datastoreName: datastoreName,
		datastorePath: filepath.Join(outputDir, datastoreName),
	}
}

// GetDatastorePath returns the full path to the datastore
func (d *DatastoreHandler) GetDatastorePath() string {
	return d.datastorePath
}

// GetOutputDir returns the output directory
func (d *DatastoreHandler) GetOutputDir() string {
	return d.outputDir
}

// GetDatastoreName returns the datastore filename
func (d *DatastoreHandler) GetDatastoreName() string {
	return d.datastoreName
}

// EnsureDatastoreDirectory creates the datastore directory if it doesn't exist
func (d *DatastoreHandler) EnsureDatastoreDirectory() error {
	datastoreDir := filepath.Dir(d.datastorePath)
	if err := EnsureDirectoryExists(datastoreDir); err != nil {
		return fmt.Errorf("failed to create datastore directory %s: %w", datastoreDir, err)
	}
	return nil
}

// UpdatePaths updates the datastore paths (useful if parameters change)
func (d *DatastoreHandler) UpdatePaths(outputDir, datastoreName string) {
	d.outputDir = outputDir
	d.datastoreName = datastoreName
	d.datastorePath = filepath.Join(outputDir, datastoreName)
}