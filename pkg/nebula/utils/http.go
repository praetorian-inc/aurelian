package utils

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/praetorian-inc/nebula/internal/logs"
)

const (
	cacheTTL = 24 * time.Hour
)

func Cached_httpGet(url string) ([]byte, error) {

	if isCacheValid(createCachedFileName(url)) {
		return readCache(createCachedFileName(url))
	} else {
		res, err := http.Get(url)
		if err != nil {
			return nil, err
		}

		defer res.Body.Close()
		body, err := io.ReadAll(res.Body)
		if err != nil {
			logs.ConsoleLogger().Error(fmt.Sprintf("Error reading response body: %v", err))
		}

		writeCache(createCachedFileName(url), body)
		return body, nil
	}
}

func createCachedFileName(url string) string {
	safeFileName := strings.ReplaceAll(url, "/", "_")
	return fmt.Sprintf("/tmp/%s.cache", safeFileName)
}

func isCacheValid(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}

	return time.Since(info.ModTime()) < cacheTTL
}

func writeCache(path string, data []byte) error {
	return os.WriteFile(path, data, 0644)
}

func readCache(path string) ([]byte, error) {
	return os.ReadFile(path)
}
