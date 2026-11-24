package cpe_test

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/cpe"
	"github.com/stretchr/testify/assert"
)

// The resolution rule: the observed version selects the vendor.
//  1. live vendors carrying exactly that version win;
//  2. else, if the product has exactly one vendor, use it;
//  3. else emit nothing — guessing produces a confidently wrong CPE.
func TestResolveVendors_VersionSelectsTheVendor(t *testing.T) {
	assert.Equal(t, []string{"apache"}, cpe.ResolveVendors("http_server", "2.4.50"))
	assert.Equal(t, []string{"redis"}, cpe.ResolveVendors("redis", "7.0.5"))
	assert.Equal(t, []string{"f5"}, cpe.ResolveVendors("nginx", "1.25.3"))
	assert.Equal(t, []string{"postgresql"}, cpe.ResolveVendors("postgresql", "15.4"))
}

func TestResolveVendors_EmptyWhenUndecidable(t *testing.T) {
	assert.Empty(t, cpe.ResolveVendors("server", "3.2.1"))      // many vendors, none carry it
	assert.Empty(t, cpe.ResolveVendors("kubernetes", "1.29.0")) // 2 vendors, neither carries it
}

// A minor-only version resolves on the strength of the *version*, not the
// vendor count. NVD's dictionary is per-patch, so no live entry carries a
// two-part version exactly — but a vendor shipping 3.12.0 through 3.12.7 is
// evidence that an observed "3.12" is theirs, and rule 1's dotted-prefix arm
// says so.
//
// Before that arm existed these all returned nothing, which meant the two
// commonest Lambda runtimes in existence (Python and Node.js) and every
// OpenSearch domain emitted no technology at all. The sole-vendor case below
// is the other half; the two are now consistent rather than falling in
// whichever direction the vendor count happened to land.
func TestResolveVendors_MinorOnlyVersionsResolveForMultiVendorProducts(t *testing.T) {
	assert.Equal(t, []string{"python"}, cpe.ResolveVendors("python", "3.12"))
	assert.Equal(t, []string{"nodejs"}, cpe.ResolveVendors("node.js", "20"))
	assert.Equal(t, []string{"elastic"}, cpe.ResolveVendors("elasticsearch", "7.10"))
	assert.Equal(t, []string{"amazon"}, cpe.ResolveVendors("opensearch", "2.11"))
}

// Widening rule 1 did not turn rule 3's silence into a guess. NVD carries no
// kubernetes 1.29 row at any granularity, so the correct answer stays empty —
// a snapshot-lag result, distinct from a release line NVD has indexed.
func TestResolveVendors_UnshippedReleaseLinesStayEmpty(t *testing.T) {
	assert.Empty(t, cpe.ResolveVendors("kubernetes", "1.29"))
	assert.Equal(t, []string{"kubernetes"}, cpe.ResolveVendors("kubernetes", "1.28"))
}

// Prefix matching widens rule 1, so it can surface a homonym the exact-match
// arm never reached. Measured instances, kept here so the cost is visible:
//
//   - `go 1` — a Lambda go1.x runtime or a public.ecr.aws/lambda/go:1 base
//     image. A bare major is the coarsest version this design can observe, and
//     it reaches both golang (correct) and ecies (a Go ECIES library). This is
//     the same accepted trade as mysql:mysql and redislabs:redis documented on
//     ResolveVendors: an inert extra node, against silently losing the real one.
//   - `influxdb 1.8` — before prefix matching this emitted eficode (a Jenkins
//     plugin that happens to publish the literal string "1.8") and *only*
//     eficode, because influxdata indexes 1.8.0-1.8.10 and never bare 1.8. The
//     widened rule restores influxdata alongside it, so the database is no
//     longer dropped in favour of the plugin.
func TestResolveVendors_PrefixMatchWidensToHomonyms(t *testing.T) {
	assert.Equal(t, []string{"ecies", "golang"}, cpe.ResolveVendors("go", "1"))
	assert.Equal(t, []string{"golang"}, cpe.ResolveVendors("go", "1.21"))

	assert.Equal(t, []string{"eficode", "influxdata"}, cpe.ResolveVendors("influxdb", "1.8"))
}

// The other half: for a sole-vendor product, rule 2 accepts *any* version,
// including an imprecise one NVD does not carry. The identification is sound —
// it is the right vendor and product — but the version is less precise than a
// dictionary entry, so guard's matcher may find no CVEs for it.
func TestResolveVendors_MinorOnlyVersionsDoResolveForSoleVendorProducts(t *testing.T) {
	assert.Equal(t, []string{"php"}, cpe.ResolveVendors("php", "8.1"))
	assert.Equal(t, []string{"ruby-lang"}, cpe.ResolveVendors("ruby", "3.2"))
	assert.Equal(t, []string{"microsoft"}, cpe.ResolveVendors(".net", "8"))
	assert.Equal(t, []string{"f5"}, cpe.ResolveVendors("nginx", "1.25"))
}

func TestResolveVendors_SoleVendorFallbackForNewerVersions(t *testing.T) {
	// A version newer than the snapshot still resolves when the product has
	// exactly one vendor. Verified against the generated table: nginx carries
	// only f5 once the deprecatedBy chain is followed across chunks.
	assert.Equal(t, []string{"f5"}, cpe.ResolveVendors("nginx", "99.99.99"))
	assert.Equal(t, []string{"apache"}, cpe.ResolveVendors("kafka", "99.99.99"))
}

func TestResolveVendors_UnknownProductResolvesToNothing(t *testing.T) {
	assert.Empty(t, cpe.ResolveVendors("this-product-does-not-exist", "1.0.0"))
	assert.Empty(t, cpe.ResolveVendors("", ""))
}

func TestResolveVendors_DeprecatedVendorsAreNeverReturned(t *testing.T) {
	// nginx:nginx and igor_sysoev:nginx are fully deprecated in favour of
	// f5:nginx. Returning either is the mis-vendoring the design forbids.
	assert.NotContains(t, cpe.ResolveVendors("nginx", "1.25.3"), "nginx")
	assert.NotContains(t, cpe.ResolveVendors("nginx", "1.25.3"), "igor_sysoev")
}

func TestResolveVendors_SiblingVendorsAreBothEmitted(t *testing.T) {
	// redis:redis and redislabs:redis are both live in the dictionary at 6.2.6,
	// so resolution cannot choose and returns both. Pinned because narrowing it
	// is a product decision, not a refactor: redislabs:redis:6.2.6 matches 0
	// CVEs while redis:redis:6.2.6 matches 22, and the two vendors' whole-product
	// CVE sets do not intersect — so collapsing either way drops real findings.
	assert.Equal(t, []string{"redis", "redislabs"}, cpe.ResolveVendors("redis", "6.2.6"))
}

func TestResolveVendors_MySQLHomonymReachesAProductionVersion(t *testing.T) {
	// A KNOWN LEAK, pinned so it is visible rather than assumed away.
	//
	// The emit-both decision rests on homonym collisions being capped at
	// versions no real deployment runs. mysql:mysql breaks that cap: it carries
	// exactly one version, 5.6.36, which an RDS engine version or a container
	// tag can genuinely be. Its CVEs at that version are CVE-2009-2942 (the
	// mysql-ocaml bindings) and CVE-2017-12419 (MantisBT) — unrelated software
	// that merely mentions MySQL — so a matcher hangs two fabricated findings on
	// an asset running Oracle MySQL.
	//
	// This is NOT asserted in the integration fixture's forbidden_cpe_substrings:
	// nothing in that fixture deploys MySQL, so the assertion would be vacuous,
	// and the behaviour it would forbid is the behaviour shipping today. When a
	// narrowing rule lands, this test is the one that should change.
	assert.Equal(t, []string{"mysql", "oracle"}, cpe.ResolveVendors("mysql", "5.6.36"),
		"if this changed, a narrowing rule landed — update the decision record on ResolveVendors")
	assert.Equal(t, []string{"oracle"}, cpe.ResolveVendors("mysql", "8.0.35"),
		"the leak is confined to the single version mysql:mysql carries")
}

func TestResolveVendors_SortedAndStable(t *testing.T) {
	got := cpe.ResolveVendors("http_server", "2.4.50")
	again := cpe.ResolveVendors("http_server", "2.4.50")
	assert.Equal(t, got, again)
	for i := 1; i < len(got); i++ {
		assert.Less(t, got[i-1], got[i], "vendors must be sorted")
	}
}

func TestTableSize_CoversTheWholeDictionary(t *testing.T) {
	// The generator fails below 40,000; assert the shipped table clears it, so
	// a truncated commit breaks the build rather than silently shrinking.
	assert.GreaterOrEqual(t, cpe.TableSize(), 40000)
}

func TestNVDSnapshot_RecordsTheFeedDate(t *testing.T) {
	assert.NotEmpty(t, cpe.NVDSnapshot)
}
