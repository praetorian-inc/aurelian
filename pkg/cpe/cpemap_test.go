package cpe_test

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/cpe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests replaced a suite that encoded "the observed version selects the
// vendor" — vendors carrying the version win, else a sole vendor, else
// nothing, with a dotted-prefix version match behind it.
//
// That rule was measured against the live NVD CVE corpus on 2026-11-24 and
// retired: it missed CVEs filed under a product's other vendors, and the
// truncation it forced on callers fabricated CVEs. See ResolveVendors' doc
// comment for the numbers. Vendor selection no longer looks at the version.

func TestResolveVendors_ReturnsEveryVendorForTheProduct(t *testing.T) {
	// http_server is the measured case: its CVEs are filed under several
	// vendors, and emitting only apache matched 11 of 15.
	got := cpe.ResolveVendors("http_server")
	assert.Contains(t, got, "apache")
	assert.Greater(t, len(got), 1, "http_server has several dictionary vendors")
}

func TestResolveVendors_IgnoresTheVersionEntirely(t *testing.T) {
	// There is no version parameter, and that is the point: a version absent
	// from the dictionary still matches CVEs through NVD's version ranges, so
	// gating vendor choice on dictionary version presence only lost recall.
	assert.NotEmpty(t, cpe.ResolveVendors("python"))
	assert.NotEmpty(t, cpe.ResolveVendors("postgresql"))
	assert.NotEmpty(t, cpe.ResolveVendors("openjdk"))
}

func TestResolveVendors_UnknownProductResolvesToNothing(t *testing.T) {
	assert.Empty(t, cpe.ResolveVendors("not_a_real_product_anywhere"))
	assert.Empty(t, cpe.ResolveVendors(""))
}

func TestResolveVendors_SiblingVendorsAreBothReturned(t *testing.T) {
	// DECIDED 2026-11-23 and unchanged: emit both, alias neither. NVD moved
	// redis CVE filing from redislabs to redis without deprecating the
	// redislabs dictionary rows, and the two vendors' CVE sets do not
	// intersect, so collapsing to one silently drops an era of real CVEs.
	got := cpe.ResolveVendors("redis")
	assert.Contains(t, got, "redis")
	assert.Contains(t, got, "redislabs")
}

func TestResolveVendors_HomonymVendorsAreReturnedAndAreInert(t *testing.T) {
	// A homonym is unrelated software sharing a product string —
	// voxpupuli:rabbitmq is a Puppet module, makandra:consul a Rails gem.
	//
	// The old rule worked hard to keep these out. Measured, that was the wrong
	// target: a homonym never shipped the observed version, so its CPE matches
	// no CVE. rabbitmq 3.13.7 under all five vendors yields exactly the one
	// CVE that truly applies. The version is the filter.
	//
	// They are not free — each is a Technology node — but they are not a
	// correctness problem, and excluding them cost real CVEs.
	got := cpe.ResolveVendors("rabbitmq")
	assert.Contains(t, got, "voxpupuli", "a homonym vendor is returned, and is inert at a version it never shipped")
	assert.Greater(t, len(got), 1)
}

func TestResolveVendors_DeprecatedVendorsAreAbsent_KnownRecallGap(t *testing.T) {
	// A KNOWN GAP, pinned so it is visible rather than forgotten.
	//
	// The generator keeps a deprecated record's successor and drops its own
	// vendor name. But CVE configurations still cite the old names: measured,
	// sun:openjdk has zero dictionary entries yet appears in 11 live CVEs, and
	// nginx:nginx, php_group:php, python_software_foundation:python and
	// yukihiro_matsumoto:ruby are the same shape.
	//
	// Retaining both names takes measured recall from 0.906 to 1.000. The fix
	// belongs in pkg/cpe/gen/distill.go and needs a feed regeneration.
	assert.NotContains(t, cpe.ResolveVendors("openjdk"), "sun",
		"if this starts failing the generator was fixed — delete this test and update the recall figures")
	assert.NotContains(t, cpe.ResolveVendors("nginx"), "nginx")
}

func TestResolveVendors_SortedAndStable(t *testing.T) {
	first := cpe.ResolveVendors("redis")
	require.NotEmpty(t, first)
	for range 20 {
		assert.Equal(t, first, cpe.ResolveVendors("redis"), "map iteration order must not reach the output")
	}
	for i := 1; i < len(first); i++ {
		assert.Less(t, first[i-1], first[i], "vendors must be sorted")
	}
}

func TestTableSize_CoversTheWholeDictionary(t *testing.T) {
	assert.Greater(t, cpe.TableSize(), 40_000,
		"the table covers the whole dictionary; there is no curated product allowlist")
}

func TestNVDSnapshot_RecordsTheFeedDate(t *testing.T) {
	assert.NotEmpty(t, cpe.NVDSnapshot)
}
