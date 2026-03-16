package publicresources

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeTestTemplate(t *testing.T, dir, name, content string) {
	t.Helper()
	err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644)
	require.NoError(t, err)
}

func TestNewLoader_LoadsExactly36Templates(t *testing.T) {
	loader, err := NewLoader()
	require.NoError(t, err)

	templates := loader.GetTemplates()
	assert.Len(t, templates, 36, "should load exactly 36 embedded YAML templates")
}

func TestNewLoader_AllTemplatesHaveRequiredFields(t *testing.T) {
	loader, err := NewLoader()
	require.NoError(t, err)

	for _, tmpl := range loader.GetTemplates() {
		t.Run(tmpl.ID, func(t *testing.T) {
			assert.NotEmpty(t, tmpl.ID, "template ID must not be empty")
			assert.NotEmpty(t, tmpl.Name, "template Name must not be empty")
			assert.NotEmpty(t, tmpl.Query, "template Query must not be empty")
			assert.NotEmpty(t, tmpl.Severity, "template Severity must not be empty")
		})
	}
}

func TestNewLoader_AllSeveritiesAreValid(t *testing.T) {
	loader, err := NewLoader()
	require.NoError(t, err)

	validSeverities := map[output.RiskSeverity]bool{
		output.RiskSeverityInfo:     true,
		output.RiskSeverityLow:      true,
		output.RiskSeverityMedium:   true,
		output.RiskSeverityHigh:     true,
		output.RiskSeverityCritical: true,
	}

	for _, tmpl := range loader.GetTemplates() {
		normalized := output.NormalizeSeverity(tmpl.Severity)
		assert.True(t, validSeverities[normalized],
			"template %s: invalid severity %q (normalized: %q)", tmpl.ID, tmpl.Severity, normalized)
	}
}

func TestNewLoader_AllTemplateIDsAreUnique(t *testing.T) {
	loader, err := NewLoader()
	require.NoError(t, err)

	seen := make(map[string]int)
	for _, tmpl := range loader.GetTemplates() {
		seen[tmpl.ID]++
	}
	for id, count := range seen {
		assert.Equal(t, 1, count, "duplicate template ID: %s (appears %d times)", id, count)
	}
}

func TestNewLoader_AllQueriesTargetResources(t *testing.T) {
	loader, err := NewLoader()
	require.NoError(t, err)

	for _, tmpl := range loader.GetTemplates() {
		t.Run(tmpl.ID, func(t *testing.T) {
			// Every ARG query should reference the Resources table or similar.
			assert.Contains(t, tmpl.Query, "esource",
				"template %s: query should reference a resource table", tmpl.ID)
		})
	}
}

func TestNewLoader_LoadUserTemplates(t *testing.T) {
	loader, err := NewLoader()
	require.NoError(t, err)

	initialCount := len(loader.GetTemplates())
	require.Equal(t, 36, initialCount)

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
	// Count should remain unchanged.
	assert.Len(t, loader.GetTemplates(), 36)
}

func TestNewLoader_LoadUserTemplates_NonexistentDir(t *testing.T) {
	loader, err := NewLoader()
	require.NoError(t, err)

	err = loader.LoadUserTemplates("/nonexistent/path")
	assert.Error(t, err)
}
