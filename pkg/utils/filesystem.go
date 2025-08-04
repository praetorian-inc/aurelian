package utils

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
)

// EnsureDirectoryExists creates a directory and all necessary parent directories
// with proper error handling and logging. It's safe to call multiple times.
func EnsureDirectoryExists(dirPath string) error {
	// Skip empty or current directory paths
	if dirPath == "" || dirPath == "." {
		return nil
	}
	
	// Convert to absolute path for better error messages
	absPath, err := filepath.Abs(dirPath)
	if err != nil {
		// Fall back to relative path if absolute conversion fails
		absPath = dirPath
	}
	
	// Check if directory already exists
	if info, err := os.Stat(absPath); err == nil {
		if info.IsDir() {
			slog.Debug("directory already exists", "path", absPath)
			return nil
		} else {
			return fmt.Errorf("path %s exists but is not a directory", absPath)
		}
	}
	
	// Create directory with appropriate permissions
	if err := os.MkdirAll(absPath, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", absPath, err)
	}
	
	slog.Debug("created directory", "path", absPath, "permissions", "0755")
	return nil
}

// EnsureOutputDirectory creates the standard nebula-output directory
// This is a convenience function for the most common use case
func EnsureOutputDirectory() error {
	return EnsureDirectoryExists("nebula-output")
}

// EnsureFileDirectory creates the directory needed for a given file path
// This extracts the directory from the file path and creates it
func EnsureFileDirectory(filePath string) error {
	dir := filepath.Dir(filePath)
	return EnsureDirectoryExists(dir)
}

// CreateOutputPath constructs a path within the nebula-output directory
// and ensures the directory structure exists
func CreateOutputPath(components ...string) (string, error) {
	// Start with nebula-output as base
	parts := append([]string{"nebula-output"}, components...)
	fullPath := filepath.Join(parts...)
	
	// Ensure the directory exists
	if err := EnsureFileDirectory(fullPath); err != nil {
		return "", fmt.Errorf("failed to create output path %s: %w", fullPath, err)
	}
	
	return fullPath, nil
}