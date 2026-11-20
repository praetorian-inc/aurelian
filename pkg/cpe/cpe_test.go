package cpe_test

import (
	"regexp"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/cpe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolve_CriteriaShape(t *testing.T) {
	assert.Equal(t, []string{"cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*"},
		cpe.Resolve("nginx", "1.25.3"))
}

func TestResolve_EmitsNothingOnBadInput(t *testing.T) {
	assert.Empty(t, cpe.Resolve("nginx", ""))
	assert.Empty(t, cpe.Resolve("nginx", "1.2:3"))
	assert.Empty(t, cpe.Resolve("no_such_product_xyz", "1.0"))
	assert.Empty(t, cpe.Resolve("", "1.0"))
}

func TestResolve_VersionSelectsTheVendor(t *testing.T) {
	// "server" carries many live vendors and none ships 3.2.1 — a naming
	// coincidence, not an identification.
	assert.Empty(t, cpe.Resolve("server", "3.2.1"))
	// redis 7.0.5 exists only under vendor "redis", not "redislabs".
	assert.Equal(t, []string{"cpe:2.3:a:redis:redis:7.0.5:*:*:*:*:*:*:*"},
		cpe.Resolve("redis", "7.0.5"))
	// http_server 2.4.50 is apache's, not ibm's or oracle's.
	assert.Equal(t, []string{"cpe:2.3:a:apache:http_server:2.4.50:*:*:*:*:*:*:*"},
		cpe.Resolve("http_server", "2.4.50"))
}

func TestResolve_SatisfiesGuardKeyRegex(t *testing.T) {
	// Versions chosen because each is a real live dictionary entry, so every
	// case produces at least one CPE — otherwise the assertion body never runs
	// and the test passes vacuously.
	re := regexp.MustCompile(`^cpe:2\.3(:[^:]+){11}$`)
	for _, tc := range []struct{ product, version string }{
		{"nginx", "1.25.3"}, {"redis", "7.0.5"},
		{"http_server", "2.4.50"}, {"postgresql", "15.4"},
	} {
		got := cpe.Resolve(tc.product, tc.version)
		require.NotEmpty(t, got, "%s %s", tc.product, tc.version)
		for _, c := range got {
			assert.Regexp(t, re, c, "product %s", tc.product)
		}
	}
}

func TestResolve_MinorOnlyVersionsEmitNothing(t *testing.T) {
	// The open version-granularity gap, pinned as behaviour: NVD's dictionary
	// is per-patch, so EKS's 1.29 and Lambda's python3.12 resolve to no vendor
	// and emit nothing rather than a guess.
	assert.Empty(t, cpe.Resolve("kubernetes", "1.29"))
	assert.Empty(t, cpe.Resolve("python", "3.12"))
	assert.Empty(t, cpe.Resolve("elasticsearch", "7.10"))
}

func TestResolve_EmitsOneCPEPerVendorCarryingTheVersion(t *testing.T) {
	// Where more than one live vendor carries the same version, all are
	// emitted: a spurious node resolves to an empty CVE set, while a missing
	// one silently loses a real one.
	got := cpe.Resolve("http_server", "2.4.50")
	assert.Len(t, got, len(cpe.ResolveVendors("http_server", "2.4.50")))
}
