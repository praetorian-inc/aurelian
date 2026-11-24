package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The reason this source exists at all.
//
// `cpe:2.3:a:sun:openjdk` appears in NVD CVE configurations — CVE-2009-0723
// among them — and has ZERO records in the CPE dictionary, deprecated or
// otherwise. Measured 2026-11-24 it is cited by 17 CVEs in the openjdk corpus.
// A table distilled from the dictionary alone can never emit it, so those CVEs
// were unreachable no matter what the resolution rule did.
func TestHarvestCVEChunk_RecordsVendorSpellingsTheDictionaryLacks(t *testing.T) {
	into := Table{}
	require.NoError(t, HarvestCVEChunk([]byte(cveOpenJDKChunk), into))

	assert.Contains(t, keys(into["openjdk"]), "sun")
}

// A CVE configuration names every product it applies to, not only the one that
// prompted the lookup. All of them are legitimate (product, vendor) evidence.
func TestHarvestCVEChunk_RecordsEveryApplicationCriteria(t *testing.T) {
	into := Table{}
	require.NoError(t, HarvestCVEChunk([]byte(cveOpenJDKChunk), into))

	assert.Contains(t, keys(into["gimp"]), "gimp")
	assert.Contains(t, keys(into["firefox"]), "mozilla")
}

// NVD nests configuration nodes to express "A running on B". A harvester that
// reads only the top level silently drops the inner operand, which is usually
// the application and always the half we care about.
func TestHarvestCVEChunk_WalksNestedChildren(t *testing.T) {
	body := []byte(`{"vulnerabilities":[{"cve":{"id":"CVE-0000-0001","configurations":[{
		"operator":"AND","nodes":[
			{"operator":"OR","cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:outer:app:1.0:*:*:*:*:*:*:*"}],
			 "children":[{"operator":"OR","cpeMatch":[
				{"vulnerable":true,"criteria":"cpe:2.3:a:inner:nested:2.0:*:*:*:*:*:*:*"}]}]}
		]}]}}]}`)

	into := Table{}
	require.NoError(t, HarvestCVEChunk(body, into))

	assert.Contains(t, keys(into["app"]), "outer")
	assert.Contains(t, keys(into["nested"]), "inner")
}

// A `vulnerable: false` criteria is the platform half of an AND — "Struts on
// Windows" names Windows so the match can be constrained, not because Windows
// is the vulnerable product. The spelling is still a real (product, vendor)
// pair NVD uses, and recording it costs a table row, not accuracy: the version
// does the filtering at resolution time.
func TestHarvestCVEChunk_RecordsNonVulnerableCriteriaToo(t *testing.T) {
	body := []byte(`{"vulnerabilities":[{"cve":{"id":"CVE-0000-0002","configurations":[{
		"nodes":[{"operator":"OR","cpeMatch":[
			{"vulnerable":false,"criteria":"cpe:2.3:a:acme:platform:1.0:*:*:*:*:*:*:*"}]}]}]}}]}`)

	into := Table{}
	require.NoError(t, HarvestCVEChunk(body, into))

	assert.Contains(t, keys(into["platform"]), "acme")
}

func TestHarvestCVEChunk_SkipsNonApplicationParts(t *testing.T) {
	body := []byte(`{"vulnerabilities":[{"cve":{"id":"CVE-0000-0003","configurations":[{
		"nodes":[{"operator":"OR","cpeMatch":[
			{"vulnerable":true,"criteria":"cpe:2.3:o:hp:hp-ux:10.20:*:*:*:*:*:*:*"},
			{"vulnerable":true,"criteria":"cpe:2.3:h:cisco:asa:1.0:*:*:*:*:*:*:*"},
			{"vulnerable":true,"criteria":"cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"}]}]}]}}]}`)

	into := Table{}
	require.NoError(t, HarvestCVEChunk(body, into))

	assert.Equal(t, []string{"widget"}, keys(into))
}

// Same contract as the dictionary pass: the table keys on unescaped literals,
// because a caller spells the product `notepad++` and must not have to know
// CPE's quoting rules. A harvester storing the escaped spelling would create a
// second, unreachable key for a product the dictionary already carries.
func TestHarvestCVEChunk_StoresUnescapedLiterals(t *testing.T) {
	body := []byte(`{"vulnerabilities":[{"cve":{"id":"CVE-0000-0004","configurations":[{
		"nodes":[{"operator":"OR","cpeMatch":[{"vulnerable":true,
			"criteria":"cpe:2.3:a:notepad-plus-plus:notepad\\+\\+:8.9.6.4:*:*:*:*:*:*:*"}]}]}]}}]}`)

	into := Table{}
	require.NoError(t, HarvestCVEChunk(body, into))

	assert.Contains(t, into, "notepad++")
	assert.NotContains(t, into, `notepad\+\+`)
}

// The two sources are a union, not alternatives: the dictionary carries names
// that exist, the CVE corpus carries names that are used, and a product is
// routinely carried by both under different vendors.
func TestHarvestCVEChunk_UnionsWithTheDictionaryPass(t *testing.T) {
	into := Table{}

	require.NoError(t, DistillChunk([]byte(nginxChunk), into))

	cve := []byte(`{"vulnerabilities":[{"cve":{"id":"CVE-0000-0005","configurations":[{
		"nodes":[{"operator":"OR","cpeMatch":[{"vulnerable":true,
			"criteria":"cpe:2.3:a:nginx:nginx:1.25.3:*:*:*:*:*:*:*"}]}]}]}}]}`)
	require.NoError(t, HarvestCVEChunk(cve, into))

	assert.Contains(t, keys(into["nginx"]), "f5", "the dictionary's live vendor survives")
	assert.Contains(t, keys(into["nginx"]), "nginx", "the CVE corpus's cited vendor is added")
}

func TestHarvestCVEChunk_RejectsMalformedBody(t *testing.T) {
	assert.Error(t, HarvestCVEChunk([]byte("not json"), Table{}))
}
