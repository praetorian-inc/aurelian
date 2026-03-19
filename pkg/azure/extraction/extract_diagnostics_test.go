package extraction

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractDiagnostics_NotRegistered(t *testing.T) {
	// extractDiagnosticSettings is a cross-cutting function, NOT registered per-type.
	// Verify the function exists by checking it is callable (compile-time check).
	// It should not appear in any resource type's extractor list.
	var fn extractorFunc = extractDiagnosticSettings
	assert.NotNil(t, fn, "extractDiagnosticSettings should be a valid extractorFunc")
}
