package graph

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewConfig(t *testing.T) {
	t.Run("creates config with provided values", func(t *testing.T) {
		cfg := NewConfig("bolt://localhost:7687", "neo4j", "password")

		assert.NotNil(t, cfg)
		assert.Equal(t, "bolt://localhost:7687", cfg.URI)
		assert.Equal(t, "neo4j", cfg.Username)
		assert.Equal(t, "password", cfg.Password)
		assert.NotNil(t, cfg.Options)
	})

	t.Run("includes sensible defaults for connection options", func(t *testing.T) {
		cfg := NewConfig("bolt://localhost:7687", "neo4j", "password")

		// Verify default options exist
		assert.Contains(t, cfg.Options, "max_connection_lifetime")
		assert.Contains(t, cfg.Options, "max_connection_pool_size")
		assert.Contains(t, cfg.Options, "connection_acquisition_timeout")

		// Verify default values match spec
		assert.Equal(t, 3600, cfg.Options["max_connection_lifetime"])
		assert.Equal(t, 50, cfg.Options["max_connection_pool_size"])
		assert.Equal(t, 60, cfg.Options["connection_acquisition_timeout"])
	})

	t.Run("allows empty URI for testing scenarios", func(t *testing.T) {
		cfg := NewConfig("", "", "")

		assert.NotNil(t, cfg)
		assert.Equal(t, "", cfg.URI)
		assert.NotNil(t, cfg.Options)
	})
}

func TestConfig_Struct(t *testing.T) {
	t.Run("Config struct fields are exported", func(t *testing.T) {
		cfg := &Config{
			URI:      "bolt://test:7687",
			Username: "user",
			Password: "pass",
			Options:  map[string]interface{}{"test": true},
		}

		assert.Equal(t, "bolt://test:7687", cfg.URI)
		assert.Equal(t, "user", cfg.Username)
		assert.Equal(t, "pass", cfg.Password)
		assert.True(t, cfg.Options["test"].(bool))
	})
}
