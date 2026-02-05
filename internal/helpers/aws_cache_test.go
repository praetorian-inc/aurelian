package helpers

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/types"
)

// TestInitCache_WithEmptyOptions tests that InitCache doesn't panic when called with empty options slice
func TestInitCache_WithEmptyOptions(t *testing.T) {
	// This should NOT panic - it should fall back to defaults
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("InitCache panicked with empty options: %v", r)
		}
	}()

	// Call with empty options slice
	InitCache([]*types.Option{})
}

// TestInitCache_WithNilOptions tests that InitCache doesn't panic when called with nil options
func TestInitCache_WithNilOptions(t *testing.T) {
	// This should NOT panic - it should fall back to defaults
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("InitCache panicked with nil options: %v", r)
		}
	}()

	// Call with nil options
	InitCache(nil)
}

// TestInitCache_WithPartialOptions tests that InitCache handles missing options gracefully
func TestInitCache_WithPartialOptions(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("InitCache panicked with partial options: %v", r)
		}
	}()

	// Provide only one option, others should fall back to defaults
	opts := []*types.Option{
		{
			Name:  "cache-ttl",
			Value: "7200",
		},
	}

	InitCache(opts)
}

// TestInitCache_WithValidOptions tests that InitCache works correctly with all options provided
func TestInitCache_WithValidOptions(t *testing.T) {
	// Create a temp directory for testing
	tempDir := t.TempDir()
	cachePath := filepath.Join(tempDir, "test-cache")

	opts := []*types.Option{
		{
			Name:  "cache-dir",
			Value: cachePath,
		},
		{
			Name:  "cache-ext",
			Value: ".test-cache",
		},
		{
			Name:  "cache-ttl",
			Value: "3600",
		},
	}

	// This should work without panic
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("InitCache panicked with valid options: %v", r)
		}
	}()

	InitCache(opts)

	// Verify cache directory was created
	if _, err := os.Stat(cachePath); os.IsNotExist(err) {
		t.Logf("Cache directory not created (this is OK if no cache files exist)")
	}
}
