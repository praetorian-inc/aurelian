//go:build integration

package integration

import (
	"fmt"
	"strings"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

// AssertResultContainsARN checks that at least one result references the given ARN.
func AssertResultContainsARN(t *testing.T, results []plugin.Result, arn string) {
	t.Helper()
	for _, r := range results {
		if containsString(r.Data, arn) {
			return
		}
	}
	t.Errorf("expected ARN %s in results (%d results checked)", arn, len(results))
}

// AssertResultContainsString checks that at least one result contains the substring.
func AssertResultContainsString(t *testing.T, results []plugin.Result, substr string) {
	t.Helper()
	for _, r := range results {
		if containsString(r.Data, substr) {
			return
		}
	}
	t.Errorf("expected %q in results (%d results checked)", substr, len(results))
}

// AssertMinResults checks that at least min results were returned.
func AssertMinResults(t *testing.T, results []plugin.Result, min int) {
	t.Helper()
	if len(results) < min {
		t.Errorf("expected at least %d results, got %d", min, len(results))
	}
}

// containsString recursively searches a value for a substring match.
func containsString(data any, substr string) bool {
	switch v := data.(type) {
	case string:
		return strings.Contains(v, substr)
	case map[string]any:
		for _, val := range v {
			if containsString(val, substr) {
				return true
			}
		}
	case []any:
		for _, val := range v {
			if containsString(val, substr) {
				return true
			}
		}
	default:
		return strings.Contains(fmt.Sprintf("%v", v), substr)
	}
	return false
}
