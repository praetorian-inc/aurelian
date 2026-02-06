package recon

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDevOpsSecretsModuleModule(t *testing.T) {
	// Test that the module is properly defined
	module := &DevOpsSecretsModule{}

	// Verify it implements plugin.Module
	var _ plugin.Module = module

	// Check required properties using plugin.Module interface methods
	if module.ID() != "devops-secrets" {
		t.Errorf("Expected id 'devops-secrets', got %v", module.ID())
	}

	if module.Platform() != plugin.PlatformAzure {
		t.Errorf("Expected platform 'azure', got %v", module.Platform())
	}

	if module.OpsecLevel() != "moderate" {
		t.Errorf("Expected opsec_level 'moderate', got %v", module.OpsecLevel())
	}

	// Check authors
	authors := module.Authors()
	if len(authors) == 0 {
		t.Error("Module authors not properly set")
	}

	if authors[0] != "Praetorian" {
		t.Errorf("Expected first author 'Praetorian', got %s", authors[0])
	}
}

// TestConvertMatchToMap tests the convertMatchToMap helper function
func TestConvertMatchToMap(t *testing.T) {
	module := &DevOpsSecretsModule{}

	t.Run("populated match", func(t *testing.T) {
		// Create a populated Match
		match := &types.Match{
			RuleName: "AWS API Key",
			RuleID:   "np.aws.1",
			Location: types.Location{
				Offset: types.OffsetSpan{
					Start: 100,
					End:   150,
				},
				Source: types.SourceSpan{
					Start: types.SourcePoint{Line: 10, Column: 5},
					End:   types.SourcePoint{Line: 10, Column: 55},
				},
			},
			Snippet: types.Snippet{
				Before:   []byte("secret = "),
				Matching: []byte("AKIAIOSFODNN7EXAMPLE"),
				After:    []byte("\nusage = prod"),
			},
		}

		result := module.convertMatchToMap(match)

		// Verify all expected keys exist
		assert.Contains(t, result, "rule")
		assert.Contains(t, result, "rule_id")
		assert.Contains(t, result, "location")
		assert.Contains(t, result, "offset_start")
		assert.Contains(t, result, "offset_end")
		assert.Contains(t, result, "snippet")
		assert.Contains(t, result, "before")
		assert.Contains(t, result, "after")

		// Verify values
		assert.Equal(t, "AWS API Key", result["rule"])
		assert.Equal(t, "np.aws.1", result["rule_id"])
		assert.Equal(t, "10:5-10:55", result["location"])
		assert.Equal(t, int64(100), result["offset_start"])
		assert.Equal(t, int64(150), result["offset_end"])
		assert.Equal(t, "AKIAIOSFODNN7EXAMPLE", result["snippet"])
		assert.Equal(t, "secret = ", result["before"])
		assert.Equal(t, "\nusage = prod", result["after"])
	})

	t.Run("nil match panics", func(t *testing.T) {
		// convertMatchToMap expects non-nil match (internal helper)
		// Verify it panics with nil (expected behavior)
		defer func() {
			r := recover()
			assert.NotNil(t, r, "Expected panic on nil match")
		}()

		var nilMatch *types.Match
		module.convertMatchToMap(nilMatch)

		// Should not reach here
		t.Fatal("Expected panic but got none")
	})

	t.Run("empty snippet", func(t *testing.T) {
		// Match with empty snippet bytes
		match := &types.Match{
			RuleName: "Empty Rule",
			RuleID:   "np.test.1",
			Location: types.Location{
				Offset: types.OffsetSpan{Start: 0, End: 0},
				Source: types.SourceSpan{
					Start: types.SourcePoint{Line: 1, Column: 1},
					End:   types.SourcePoint{Line: 1, Column: 1},
				},
			},
			Snippet: types.Snippet{
				Before:   []byte(""),
				Matching: []byte(""),
				After:    []byte(""),
			},
		}

		result := module.convertMatchToMap(match)

		assert.Equal(t, "", result["snippet"])
		assert.Equal(t, "", result["before"])
		assert.Equal(t, "", result["after"])
	})
}

// TestRunNoseyParker tests the runNoseyParker function with directory scanning
func TestRunNoseyParker(t *testing.T) {
	module := &DevOpsSecretsModule{}
	ctx := context.Background()

	t.Run("detects AWS key in file", func(t *testing.T) {
		// Create temp directory with test file
		tmpDir := t.TempDir()
		testFile := filepath.Join(tmpDir, "config.txt")

		// Write a known secret pattern (AWS access key format)
		testContent := `
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
`
		err := os.WriteFile(testFile, []byte(testContent), 0644)
		require.NoError(t, err)

		// Run scanner
		findings, err := module.runNoseyParker(ctx, testFile, false, io.Discard)

		// Should not error
		assert.NoError(t, err)

		// Should find at least one secret
		assert.NotEmpty(t, findings, "Expected to find at least one secret")

		// Verify finding structure
		if len(findings) > 0 {
			finding := findings[0]
			assert.Contains(t, finding, "rule")
			assert.Contains(t, finding, "rule_id")
			assert.Contains(t, finding, "location")
			assert.NotEmpty(t, finding["rule"], "Expected rule name to be populated")
		}
	})

	t.Run("no secrets in clean file", func(t *testing.T) {
		// Create temp directory with clean file
		tmpDir := t.TempDir()
		testFile := filepath.Join(tmpDir, "clean.txt")

		// Write content without secrets
		testContent := "This is just a regular file with no secrets.\n"
		err := os.WriteFile(testFile, []byte(testContent), 0644)
		require.NoError(t, err)

		// Run scanner
		findings, err := module.runNoseyParker(ctx, testFile, false, io.Discard)

		// Should not error
		assert.NoError(t, err)

		// Should find no secrets
		assert.Empty(t, findings, "Expected no secrets in clean file")
	})

	t.Run("nonexistent file returns error", func(t *testing.T) {
		// Try to scan nonexistent file
		findings, err := module.runNoseyParker(ctx, "/nonexistent/path/file.txt", false, io.Discard)

		// Should error
		assert.Error(t, err)
		assert.Nil(t, findings)
	})
}

// TestScanTextWithNoseyParker tests the scanTextWithNoseyParker function
func TestScanTextWithNoseyParker(t *testing.T) {
	module := &DevOpsSecretsModule{}
	ctx := context.Background()

	t.Run("detects secret in text", func(t *testing.T) {
		// Text containing known secret pattern
		testText := `
apiVersion: v1
kind: Secret
metadata:
  name: my-secret
data:
  api-key: AKIAIOSFODNN7EXAMPLE
  password: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
`

		// Run scanner
		findings, err := module.scanTextWithNoseyParker(ctx, testText, false, io.Discard)

		// Should not error
		assert.NoError(t, err)

		// Should find at least one secret
		assert.NotEmpty(t, findings, "Expected to find at least one secret")

		// Verify finding structure
		if len(findings) > 0 {
			finding := findings[0]
			assert.Contains(t, finding, "rule")
			assert.Contains(t, finding, "snippet")

			// Should detect an AWS-related rule
			ruleName := finding["rule"].(string)
			assert.True(t, strings.Contains(strings.ToLower(ruleName), "aws") ||
				strings.Contains(strings.ToLower(ruleName), "key"),
				"Expected AWS or key-related rule name, got: %s", ruleName)
		}
	})

	t.Run("no secrets in clean text", func(t *testing.T) {
		// Clean text without secrets
		testText := "This is just regular text with no sensitive information."

		// Run scanner
		findings, err := module.scanTextWithNoseyParker(ctx, testText, false, io.Discard)

		// Should not error
		assert.NoError(t, err)

		// Should find no secrets
		assert.Empty(t, findings, "Expected no secrets in clean text")
	})

	t.Run("empty text", func(t *testing.T) {
		// Empty text
		testText := ""

		// Run scanner
		findings, err := module.scanTextWithNoseyParker(ctx, testText, false, io.Discard)

		// Should not error
		assert.NoError(t, err)

		// Should find no secrets
		assert.Empty(t, findings)
	})
}
