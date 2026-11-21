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
