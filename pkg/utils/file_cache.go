package utils

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	cacheTTL = 24 * time.Hour
)

func CreateCachedFileName(url string) string {
	safeFileName := strings.ReplaceAll(url, "/", "_") + ".cache"
	return filepath.Join(os.TempDir(), safeFileName)
}

func IsCacheValid(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}

	return time.Since(info.ModTime()) < cacheTTL
}

func WriteCache(path string, data []byte) error {
	return os.WriteFile(path, data, 0644)
}

func ReadCache(path string) ([]byte, error) {
	return os.ReadFile(path)
}
