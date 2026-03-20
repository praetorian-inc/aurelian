package utils

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const defaultCacheTTL = 24 * time.Hour

// CachedHTTPClient performs HTTP GETs with a file-based cache.
type CachedHTTPClient struct {
	TTL time.Duration
}

// Get fetches the URL, returning a cached response if one exists within the TTL.
func (c *CachedHTTPClient) Get(url string) ([]byte, error) {
	path := c.CacheKey(url)

	if c.IsCacheValid(path) {
		return c.ReadCache(path)
	}

	resp, err := http.Get(url) //nolint:noctx
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response from %s: %w", url, err)
	}

	_ = c.WriteCache(path, body)

	return body, nil
}

// CacheKey returns the filesystem path used to cache the given URL.
func (c *CachedHTTPClient) CacheKey(url string) string {
	return filepath.Join(os.TempDir(), strings.ReplaceAll(url, "/", "_")+".cache")
}

// IsCacheValid reports whether a cached file exists and is within the TTL.
func (c *CachedHTTPClient) IsCacheValid(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	ttl := c.TTL
	if ttl == 0 {
		ttl = defaultCacheTTL
	}
	return time.Since(info.ModTime()) < ttl
}

// ReadCache reads a cached response from disk.
func (c *CachedHTTPClient) ReadCache(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// WriteCache writes a response to the cache file.
func (c *CachedHTTPClient) WriteCache(path string, data []byte) error {
	return os.WriteFile(path, data, 0644)
}
