//go:build integration

// Uses the recon_test external package to match the existing integration
// tests in this directory.
package recon_test

import (
	"os"
	"testing"

	"github.com/praetorian-inc/aurelian/test/testutil/fixture"
)

func TestMain(m *testing.M) { os.Exit(fixture.RunTests(m)) }
