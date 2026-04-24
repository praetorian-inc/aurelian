//go:build integration

package extraction

import (
	"os"
	"testing"

	"github.com/praetorian-inc/aurelian/test/testutil/fixture"
)

func TestMain(m *testing.M) { os.Exit(fixture.RunTests(m)) }
