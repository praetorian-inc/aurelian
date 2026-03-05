package azure

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeTestTemplate(t *testing.T, dir, name, content string) {
	t.Helper()
	err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644)
	require.NoError(t, err)
}

func TestNewLoader_LoadsEmbeddedTemplates(t *testing.T) {
	loader, err := NewLoader()
	require.NoError(t, err)

	templates := loader.GetTemplates()
	assert.NotEmpty(t, templates, "should load embedded YAML templates")
	assert.GreaterOrEqual(t, len(templates), 30, "should have at least 30 templates")
}

func TestNewLoader_AllTemplatesHaveRequiredFields(t *testing.T) {
	loader, err := NewLoader()
	require.NoError(t, err)

	for _, tmpl := range loader.GetTemplates() {
		assert.NotEmpty(t, tmpl.ID, "template ID must not be empty")
		assert.NotEmpty(t, tmpl.Name, "template Name must not be empty")
		assert.NotEmpty(t, tmpl.Query, "template Query must not be empty")
		assert.NotEmpty(t, tmpl.Severity, "template Severity must not be empty for %s", tmpl.ID)
	}
}

func TestNewLoader_LoadUserTemplates(t *testing.T) {
	loader, err := NewLoader()
	require.NoError(t, err)

	initialCount := len(loader.GetTemplates())

	dir := t.TempDir()
	writeTestTemplate(t, dir, "test_template.yaml", `
id: test_custom
name: Test Custom Template
description: A test template
severity: Low
query: "resources | where type == 'test'"
category: ["Public Access"]
`)

	err = loader.LoadUserTemplates(dir)
	require.NoError(t, err)
	assert.Equal(t, initialCount+1, len(loader.GetTemplates()))
}

func TestNewLoader_LoadUserTemplates_EmptyDir(t *testing.T) {
	loader, err := NewLoader()
	require.NoError(t, err)

	err = loader.LoadUserTemplates("")
	require.NoError(t, err)
}

func TestNewLoader_LoadUserTemplates_NonexistentDir(t *testing.T) {
	loader, err := NewLoader()
	require.NoError(t, err)

	err = loader.LoadUserTemplates("/nonexistent/path")
	assert.Error(t, err)
}
