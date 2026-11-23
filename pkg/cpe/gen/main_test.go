package main

import (
	"os"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type table = map[string]map[string]map[string]struct{} // product -> vendor -> versions

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestDistillChunk_DropsDeprecated(t *testing.T) {
	body, err := os.ReadFile("../testdata/nvd/nginx.json")
	require.NoError(t, err)
	into := table{}
	require.NoError(t, DistillChunk(body, into))
	vendors := keys(into["nginx"])
	assert.Contains(t, vendors, "f5")
	assert.NotContains(t, vendors, "nginx")       // deprecated
	assert.NotContains(t, vendors, "igor_sysoev") // deprecated
}

func TestDistillChunk_RecordsVersionsPerVendor(t *testing.T) {
	body, err := os.ReadFile("../testdata/nvd/nginx.json")
	require.NoError(t, err)
	into := table{}
	require.NoError(t, DistillChunk(body, into))
	assert.Contains(t, into["nginx"]["f5"], "1.25.3")
}

func TestDistillChunk_AccumulatesAcrossChunks(t *testing.T) {
	into := table{}
	for _, f := range []string{"nginx.json", "redis.json"} {
		body, err := os.ReadFile("../testdata/nvd/" + f)
		require.NoError(t, err)
		require.NoError(t, DistillChunk(body, into))
	}
	assert.Contains(t, into, "nginx")
	assert.Contains(t, into, "redis")
}

func TestDistillChunk_FollowsDeprecatedByChain(t *testing.T) {
	// nginx traces igor_sysoev -> nginx -> f5 via deprecatedBy. Given only
	// deprecated records, the resolver must land on the live successor.
	body, err := os.ReadFile("../testdata/nvd/nginx-deprecated-only.json")
	require.NoError(t, err)
	into := table{}
	require.NoError(t, DistillChunk(body, into))
	assert.Equal(t, []string{"f5"}, keys(into["nginx"]))
}

// The real feed splits the nginx rename chain across chunks: igor_sysoev:nginx
// records sit in chunk 1 while the nginx:nginx records they are deprecated by
// span chunks 1-8, and nginx:nginx has no live record at all. Resolving
// deprecatedBy against one chunk therefore stops at nginx:nginx and records
// `nginx` as a live vendor — the exact mis-vendoring (nginx:nginx instead of
// f5:nginx) the design's anti-goals name. The chain must resolve against an
// index of the whole feed.
func TestDistill_FollowsDeprecatedByAcrossChunks(t *testing.T) {
	chunkA := []byte(`{"products":[
		{"cpe":{"cpeName":"cpe:2.3:a:igor_sysoev:nginx:1.0.0:*:*:*:*:*:*:*","deprecated":true,
		 "deprecatedBy":[{"cpeName":"cpe:2.3:a:nginx:nginx:1.0.0:*:*:*:*:*:*:*"}]}}
	]}`)
	chunkB := []byte(`{"products":[
		{"cpe":{"cpeName":"cpe:2.3:a:nginx:nginx:1.0.0:*:*:*:*:*:*:*","deprecated":true,
		 "deprecatedBy":[{"cpeName":"cpe:2.3:a:f5:nginx:1.0.0:*:*:*:*:*:*:*"}]}}
	]}`)

	idx := DeprecationIndex{}
	for _, c := range [][]byte{chunkA, chunkB} {
		require.NoError(t, IndexChunk(c, idx))
	}
	into := table{}
	for _, c := range [][]byte{chunkA, chunkB} {
		require.NoError(t, DistillChunkWithIndex(c, into, idx))
	}

	assert.Equal(t, []string{"f5"}, keys(into["nginx"]))
	assert.Contains(t, into["nginx"]["f5"], "1.0.0")
}

func TestDistillChunk_KeepsEveryLiveVendorForAProduct(t *testing.T) {
	// redis is carried by several simultaneously live vendors; the generator
	// keeps all of them, and the resolution rule discriminates on version.
	body, err := os.ReadFile("../testdata/nvd/redis.json")
	require.NoError(t, err)
	into := table{}
	require.NoError(t, DistillChunk(body, into))
	vendors := keys(into["redis"])
	assert.Contains(t, vendors, "redis")
	assert.Contains(t, vendors, "redislabs")
	assert.Contains(t, into["redis"]["redis"], "7.0.5")
}

func TestDistillChunk_SkipsNonApplicationParts(t *testing.T) {
	body := []byte(`{"products":[
		{"cpe":{"cpeName":"cpe:2.3:o:linux:linux_kernel:6.1:*:*:*:*:*:*:*","deprecated":false}},
		{"cpe":{"cpeName":"cpe:2.3:h:cisco:asa:1.0:*:*:*:*:*:*:*","deprecated":false}},
		{"cpe":{"cpeName":"cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*","deprecated":false}}
	]}`)
	into := table{}
	require.NoError(t, DistillChunk(body, into))
	assert.Equal(t, []string{"widget"}, keys(into))
}

// Table keys are unescaped literals. NVD publishes `notepad\+\+`; a caller of
// ResolveVendors spells the product `notepad++` and must not have to know CPE's
// quoting rules.
func TestDistillChunk_StoresUnescapedLiterals(t *testing.T) {
	body := []byte(`{"products":[
		{"cpe":{"cpeName":"cpe:2.3:a:notepad-plus-plus:notepad\\+\\+:8.9.6.4:*:*:*:*:*:*:*","deprecated":false}},
		{"cpe":{"cpeName":"cpe:2.3:a:1c:1c\\:enterprise:8.3.13:*:*:*:*:*:*:*","deprecated":false}}
	]}`)
	into := table{}
	require.NoError(t, DistillChunk(body, into))

	assert.Contains(t, into, "notepad++")
	assert.NotContains(t, into, `notepad\+\+`)
	assert.Contains(t, into["notepad++"], "notepad-plus-plus")
	assert.Contains(t, into["notepad++"]["notepad-plus-plus"], "8.9.6.4")

	// A product whose NVD spelling escapes a colon keys on the literal colon.
	assert.Contains(t, into, "1c:enterprise")
	assert.Contains(t, into["1c:enterprise"], "1c")
}

func TestDistillChunk_RejectsMalformedBody(t *testing.T) {
	into := table{}
	assert.Error(t, DistillChunk([]byte("not json"), into))
}
