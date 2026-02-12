package utils

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
)

func EnsureDirectoryExists(dirPath string) error {
	if dirPath == "" || dirPath == "." {
		return nil
	}

	absPath, err := filepath.Abs(dirPath)
	if err != nil {
		absPath = dirPath
	}

	if info, err := os.Stat(absPath); err == nil {
		if info.IsDir() {
			slog.Debug("directory already exists", "path", absPath)
			return nil
		} else {
			return fmt.Errorf("path %s exists but is not a directory", absPath)
		}
	}

	if err := os.MkdirAll(absPath, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", absPath, err)
	}

	slog.Debug("created directory", "path", absPath, "permissions", "0755")
	return nil
}

func EnsureOutputDirectory() error {
	return EnsureDirectoryExists("aurelian-output")
}

func EnsureFileDirectory(filePath string) error {
	dir := filepath.Dir(filePath)
	return EnsureDirectoryExists(dir)
}

func CreateOutputPath(components ...string) (string, error) {

	parts := append([]string{"aurelian-output"}, components...)
	fullPath := filepath.Join(parts...)

	if err := EnsureFileDirectory(fullPath); err != nil {
		return "", fmt.Errorf("failed to create output path %s: %w", fullPath, err)
	}

	return fullPath, nil
}
