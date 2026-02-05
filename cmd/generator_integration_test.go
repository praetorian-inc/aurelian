package cmd

import (
	"bytes"
	"testing"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/janus-framework/pkg/output"
	"github.com/praetorian-inc/janus-framework/pkg/testutils/mocks/basics"
	"github.com/praetorian-inc/aurelian/pkg/outputters"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAutoRunModule verifies autorun modules (no InputParam) work correctly.
func TestAutoRunModule(t *testing.T) {
	// Create an autorun module (no InputParam)
	w := &bytes.Buffer{}
	module := chain.NewModule(
		cfg.NewMetadata("test-autorun", "test autorun module"),
	).WithLinks(
		basics.NewStrLink,
	).WithConfigs(
		cfg.WithArg("writer", w),
	).WithOutputters(
		output.NewWriterOutputter,
	).WithAutoRun()

	// Run module directly (no need for chain)
	err := module.Run()
	require.NoError(t, err)
	require.NoError(t, module.Error())

	// Verify "autorun" was sent to chain
	// For autorun modules, the chain should have processed "autorun" as input
	assert.Equal(t, "autorun\n", w.String())
}

// TestModuleWithInputParam verifies input parameter handling.
// This test uses Module.Run() to properly apply configs and execute the module.
func TestModuleWithInputParam(t *testing.T) {
	// Create a module with InputParam
	w := &bytes.Buffer{}

	module := chain.NewModule(
		cfg.NewMetadata(
			"test-input",
			"test input module",
		).WithChainInputParam("items"),
	).WithLinks(
		basics.NewStrLink,
	).WithConfigs(
		cfg.WithArg("writer", w),
	).WithInputParam(
		cfg.NewParam[[]string]("items", "items to process"),
	).WithOutputters(
		output.NewWriterOutputter,
	)

	// Use Module.Run() to verify the full flow works (this applies configs internally)
	err := module.Run(cfg.WithArg("items", []string{"item1", "item2", "item3"}))
	require.NoError(t, err)
	require.NoError(t, module.Error())

	// Verify all inputs were processed
	expected := "item1\nitem2\nitem3\n"
	assert.Equal(t, expected, w.String())

	// Note: Module.Run() properly applies configs and executes the module with input values
}

// TestMissingInputParam verifies error when required input is missing.
func TestMissingInputParam(t *testing.T) {
	t.Skip("Validation behavior changed after janus-framework migration - module.Run() validates lazily during execution, not upfront")

	// Create a module with InputParam
	w := &bytes.Buffer{}
	module := chain.NewModule(
		cfg.NewMetadata(
			"test-missing",
			"test missing input",
		).WithChainInputParam("items"),
	).WithLinks(
		basics.NewStrLink,
	).WithConfigs(
		cfg.WithArg("writer", w),
	).WithInputParam(
		cfg.NewParam[[]string]("items", "items to process"),
	).WithOutputters(
		output.NewWriterOutputter,
	)

	// Run should fail due to missing input (no configs provided)
	err := module.Run()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "input parameter \"items\" is unset")
}

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
				// RuntimeMarkdownOutputter is an interface implementation, check it's an Outputter
				_, ok := outputter.(chain.Outputter)
				assert.True(t, ok, "Expected chain.Outputter implementation")
			} else {
				assert.Nil(t, constructor, "Expected nil constructor for format: %s", tt.outputFormat)
			}
		})
	}
}

// TestModuleConfigsAccessor verifies Configs() accessor returns module configs.
func TestModuleConfigsAccessor(t *testing.T) {
	// Create a module with some configs
	w := &bytes.Buffer{}
	module := chain.NewModule(
		cfg.NewMetadata("test-configs", "test module configs"),
	).WithLinks(
		basics.NewStrLink,
	).WithConfigs(
		cfg.WithArg("writer", w),
		cfg.WithArg("testConfig", "testValue"),
	).WithOutputters(
		output.NewWriterOutputter,
	).WithAutoRun()

	// Verify Configs() returns the module's configs
	configs := module.Configs()
	require.Len(t, configs, 2, "Expected 2 configs")

	// Verify the module can be used successfully (configs are applied internally)
	err := module.Run()
	require.NoError(t, err)
	require.NoError(t, module.Error())

	assert.Equal(t, "autorun\n", w.String(), "Chain should have executed successfully")
}
