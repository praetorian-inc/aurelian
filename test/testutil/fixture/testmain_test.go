//go:build integration

package fixture

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) { os.Exit(RunTests(m)) }
