package cpe_test

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The package's value is that an open-source clone compiles it with no
// aurelian context: it takes a product and a version and returns CPE strings,
// and the caller wraps those into whatever model it needs. That is a property
// worth a test rather than a convention.
const selfPath = "github.com/praetorian-inc/aurelian/pkg/cpe"

func TestPackageIsStandalone(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	require.NoError(t, err)
	for dep := range strings.SplitSeq(string(out), "\n") {
		dep = strings.TrimSpace(dep)
		if dep == "" || dep == selfPath {
			// `go list -deps` lists the package under test among its own deps.
			continue
		}
		assert.NotContains(t, dep, "praetorian-inc/aurelian/pkg/",
			"pkg/cpe must not import aurelian packages")
	}
}

// The committed table is what makes `go generate` optional for a consumer: the
// detectors are pure, and nothing reaches the network at build or test time.
func TestPackageMakesNoNetworkCallsAtRuntime(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	require.NoError(t, err)
	for dep := range strings.SplitSeq(string(out), "\n") {
		assert.NotEqual(t, "net/http", strings.TrimSpace(dep),
			"pkg/cpe must not depend on net/http; the NVD fetch lives in pkg/cpe/gen")
	}
}
