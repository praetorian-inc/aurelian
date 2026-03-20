//go:build integration

package testutil

import (
	"strings"
	"testing"

	"github.com/praetorian-inc/aurelian/test/testutil/fixture"
)

// Fixture is an alias so callers can continue using testutil.Fixture.
type Fixture = fixture.Fixture

// NewFixture returns a provider-specific fixture based on the moduleDir prefix.
func NewFixture(t *testing.T, moduleDir string) Fixture {
	t.Helper()

	switch {
	case strings.HasPrefix(moduleDir, "aws/"):
		return NewAWSFixture(t, moduleDir)
	case strings.HasPrefix(moduleDir, "azure/"):
		return NewAzureFixture(t, moduleDir)
	case strings.HasPrefix(moduleDir, "gcp/"):
		return NewGCPFixture(t, moduleDir)
	default:
		t.Fatalf("unsupported fixture provider prefix in %q", moduleDir)
		return nil
	}
}
