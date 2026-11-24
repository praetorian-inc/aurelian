package cpe_test

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/cpe"
	"github.com/stretchr/testify/assert"
)

func TestNormalizeVersion(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"1.25.3-alpine", "1.25.3"},
		{"1.18.0-6ubuntu14", "1.18.0"},
		{"15.4", "15.4"},
		{"20", "20"},
		{"v3.5.9", "3.5.9"},
		{"latest", ""},
		{"stable", ""},
		{"edge", ""},
		{"", ""},
		{"sha256:abc123", ""},
		{"1.2:3", ""},
	} {
		assert.Equal(t, tc.want, cpe.NormalizeVersion(tc.in), "input %q", tc.in)
	}
}

func TestNormalizeVersion_DropsSuffixesRatherThanRelocatingThem(t *testing.T) {
	// The version is the dotted numeric prefix only. Distro and variant
	// suffixes are dropped, never moved to target_sw.
	for _, tc := range []struct{ in, want string }{
		{"8.0.32-0ubuntu0.22.04.2", "8.0.32"},
		{"7.0.5-rc1", "7.0.5"},
		{"3.11.4+deb12u1", "3.11.4"},
		{"2.4.50_1", "2.4.50"},
		{"1.25.3.", "1.25.3"}, // a trailing dot is not part of the version
	} {
		assert.Equal(t, tc.want, cpe.NormalizeVersion(tc.in), "input %q", tc.in)
	}
}

func TestNormalizeVersion_RequiresALeadingDigit(t *testing.T) {
	// "A version must have at least a major component to emit."
	for _, in := range []string{"alpine", "bookworm-slim", "-1.2.3", ".1.2", "v", "vnext"} {
		assert.Equal(t, "", cpe.NormalizeVersion(in), "input %q", in)
	}
}

func TestNormalizeVersion_OutputIsSafeForCPEAssembly(t *testing.T) {
	// Whatever NormalizeVersion returns must be assemblable: no colon, no
	// whitespace, nothing that would push the bound string past thirteen
	// components.
	for _, in := range []string{"1.25.3-alpine", "15.4", "8.0.mysql_aurora.3.04.0", "1.2:3", "sha256:abc"} {
		got := cpe.NormalizeVersion(in)
		assert.NotContains(t, got, ":", "input %q", in)
		assert.NotContains(t, got, " ", "input %q", in)
	}
}

// Both cases below were found by harvesting real image config blobs. Each
// one costs a real
// emission: cpe.Resolve("openjdk", "25.0.5.1") and
// cpe.Resolve("mariadb", "11.8.9") both resolve, so the only thing standing
// between the observed marker and a correct CPE was normalisation.
func TestNormalizeVersion_StripsJDKDistributionPrefix(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"jdk-25.0.5.1+2", "25.0.5.1"},   // tomcat:10 JAVA_VERSION
		{"jdk-17.0.21.1+2", "17.0.21.1"}, // eclipse-temurin:17-jre JAVA_VERSION
		{"openjdk-17.0.9", "17.0.9"},
		{"jdk-", ""},  // prefix with nothing behind it is not a version
		{"jdked", ""}, // not the prefix; still fails the leading-digit rule
	} {
		assert.Equal(t, tc.want, cpe.NormalizeVersion(tc.in), "input %q", tc.in)
	}
}

func TestNormalizeVersion_StripsDebianEpoch(t *testing.T) {
	// mariadb:11 ships MARIADB_VERSION=1:11.8.9+maria~ubu2404. A leading
	// "<digits>:" is a Debian/RPM epoch, which is a well-defined thing and not
	// the compound identifier the colon rule exists to distrust.
	for _, tc := range []struct{ in, want string }{
		{"1:11.8.9+maria~ubu2404", "11.8.9"},
		{"2:1.2.3", "1.2.3"},
		{"0:9.1", "9.1"},
	} {
		assert.Equal(t, tc.want, cpe.NormalizeVersion(tc.in), "input %q", tc.in)
	}
}

func TestNormalizeVersion_EpochStripIsNotAGeneralColonEscape(t *testing.T) {
	// Only a leading all-digit epoch is stripped. Everything else containing a
	// colon stays rejected — the rule protects digests and compound
	// identifiers, and loosening it further would turn "1.2:3" into "1.2".
	for _, in := range []string{
		"sha256:abc123",
		"1.2:3",
		"8.0.mysql_aurora:3.04.0",
		"1:2:3",     // more than one colon is not an epoch
		"v1:2.3",    // epoch must lead, not follow a prefix
		":1.2.3",    // empty epoch
		"abc:1.2.3", // non-numeric epoch
	} {
		assert.Equal(t, "", cpe.NormalizeVersion(in), "input %q", in)
	}
}
