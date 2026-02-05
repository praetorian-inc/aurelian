package cmd

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/outputters"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// SKIPPED: TestAutoRunModule
// Reason: Tests Janus chain module behavior, not applicable to native plugin pattern

// SKIPPED: TestModuleWithInputParam
// Reason: Tests Janus chain module input parameter handling, not applicable to native plugin pattern

// SKIPPED: TestMissingInputParam
// Reason: Tests Janus chain module validation behavior, not applicable to native plugin pattern

// TestOutputterSelection_Integration verifies outputter selection integrates correctly.
func TestOutputterSelection_Integration(t *testing.T) {
	tests := []struct {
		name                 string
		outputFormat         string
		expectJSONStream     bool
		expectRuntimeMarkdown bool
	}{
		{
			name:             "JSON format selects JSONStreamOutputter",
			outputFormat:     OutputFormatJSON,
			expectJSONStream: true,
		},
		{
			name:                 "Markdown format selects RuntimeMarkdownOutputter",
			outputFormat:         OutputFormatMarkdown,
			expectRuntimeMarkdown: true,
		},
		{
			name:         "Default format returns nil",
			outputFormat: OutputFormatDefault,
		},
		{
			name:         "Empty format returns nil",
			outputFormat: "",
		},
		{
			name:         "Unknown format returns nil",
			outputFormat: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			constructor := SelectOutputter(tt.outputFormat)

			if tt.expectJSONStream {
				require.NotNil(t, constructor, "Expected non-nil constructor for JSON format")
				outputter := constructor()
				require.NotNil(t, outputter, "Constructor returned nil outputter")
				_, ok := outputter.(*outputters.FormatterAdapter)
				assert.True(t, ok, "Expected *outputters.FormatterAdapter, got %T", outputter)
			} else if tt.expectRuntimeMarkdown {
				require.NotNil(t, constructor, "Expected non-nil constructor for markdown format")
				outputter := constructor()
				require.NotNil(t, outputter, "Constructor returned nil outputter")
				// RuntimeMarkdownOutputter is native outputter, verify it exists
				assert.NotNil(t, outputter, "Expected non-nil outputter")
			} else {
				assert.Nil(t, constructor, "Expected nil constructor for format: %s", tt.outputFormat)
			}
		})
	}
}

// SKIPPED: TestModuleConfigsAccessor
// Reason: Tests Janus chain module config accessor, not applicable to native plugin pattern
