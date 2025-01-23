package helpers

import (
	"os"
	"path/filepath"
)

func FindBinary(name string) (string, error) {
	// check if they provied an absolute path
	full, err := filepath.Abs(name)
	if err != nil {
		return "", err
	}
	found, err := os.Stat(full)
	if err == nil {
		if found.Mode()&0111 != 0 {
			return full, nil
		}

	}

	// Get PATH environment variable
	pathEnv := os.Getenv("PATH")

	// Split PATH into individual directories
	paths := filepath.SplitList(pathEnv)

	// Search each directory in PATH
	for _, path := range paths {
		// Construct full path to potential binary
		fullPath := filepath.Join(path, name)

		// Check if file exists and is executable
		fileInfo, err := os.Stat(fullPath)
		if err == nil {
			// On Unix-like systems, check if the file is executable
			if fileInfo.Mode()&0111 != 0 {
				return fullPath, nil
			}
		}
	}

	return "", os.ErrNotExist
}
