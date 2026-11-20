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

func TestResolveVendors_MinorOnlyVersionsDoNotResolve(t *testing.T) {
	// NVD's dictionary is per-patch. EKS reports 1.29, Lambda python3.12 and
	// OpenSearch Elasticsearch_7.10, and no live entry carries those two-part
	// versions, so rule 3 fires. This pins the open "version-granularity gap"
	// as it actually behaves rather than as an earlier draft assumed.
	assert.Empty(t, cpe.ResolveVendors("kubernetes", "1.29"))
	assert.Empty(t, cpe.ResolveVendors("python", "3.12"))
	assert.Empty(t, cpe.ResolveVendors("elasticsearch", "7.10"))
	assert.Empty(t, cpe.ResolveVendors("opensearch", "2.11"))
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
