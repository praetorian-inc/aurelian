package cpe_test

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/cpe"
	"github.com/stretchr/testify/assert"
)

// Every row below is measured against the committed cpemap.json.gz, from the
// markers harvested in pkg/software/testdata/imageconfig/FINDINGS.md.
//
// The point of ResolveBestEffort is that NVD's dictionary lags current patch
// releases: a config blob reports the exact version an image runs, and for
// over half the common images that exact version has no dictionary row while a
// shorter prefix of it does.
func TestResolveBestEffort_FullPrecisionIsKeptWhereItResolves(t *testing.T) {
	// A regression that truncated any of these would be a silent precision
	// loss: the emission still appears, just against a wider CVE set.
	for _, tc := range []struct{ product, version, want string }{
		{"nginx", "1.25.5", "cpe:2.3:a:f5:nginx:1.25.5:*:*:*:*:*:*:*"},
		{"http_server", "2.4.71", "cpe:2.3:a:apache:http_server:2.4.71:*:*:*:*:*:*:*"},
		{"haproxy", "2.9.15", "cpe:2.3:a:haproxy:haproxy:2.9.15:*:*:*:*:*:*:*"},
		{"tomcat", "10.1.62", "cpe:2.3:a:apache:tomcat:10.1.62:*:*:*:*:*:*:*"},
		{"ruby", "3.3.14", "cpe:2.3:a:ruby-lang:ruby:3.3.14:*:*:*:*:*:*:*"},
		{"php", "8.3.37", "cpe:2.3:a:php:php:8.3.37:*:*:*:*:*:*:*"},
		{"go", "1.23.12", "cpe:2.3:a:golang:go:1.23.12:*:*:*:*:*:*:*"},
		{".net", "8.0.34", "cpe:2.3:a:microsoft:.net:8.0.34:*:*:*:*:*:*:*"},
		{"openjdk", "25.0.5.1", "cpe:2.3:a:oracle:openjdk:25.0.5.1:*:*:*:*:*:*:*"},
	} {
		got, precision := cpe.ResolveBestEffort(tc.product, tc.version)
		assert.Equal(t, []string{tc.want}, got, "%s %s", tc.product, tc.version)
		assert.Equal(t, tc.version, precision, "%s %s must not be truncated", tc.product, tc.version)
	}
}

func TestResolveBestEffort_TruncatesToTheNearestResolvableePrefix(t *testing.T) {
	for _, tc := range []struct{ product, version, wantPrecision, want string }{
		{"python", "3.11.18", "3.11", "cpe:2.3:a:python:python:3.11:*:*:*:*:*:*:*"},
		{"node.js", "20.20.2", "20.20", "cpe:2.3:a:nodejs:node.js:20.20:*:*:*:*:*:*:*"},
		{"redis", "7.4.12", "7.4", "cpe:2.3:a:redis:redis:7.4:*:*:*:*:*:*:*"},
		{"memcached", "1.6.45", "1.6", "cpe:2.3:a:memcached:memcached:1.6:*:*:*:*:*:*:*"},
		{"mongodb", "7.0.48", "7.0", "cpe:2.3:a:mongodb:mongodb:7.0:*:*:*:*:*:*:*"},
		{"mysql", "8.4.13.1", "8.4", "cpe:2.3:a:oracle:mysql:8.4:*:*:*:*:*:*:*"},
		{"jenkins", "2.580.2", "2.580", "cpe:2.3:a:jenkins:jenkins:2.580:*:*:*:*:*:*:*"},
	} {
		got, precision := cpe.ResolveBestEffort(tc.product, tc.version)
		assert.Equal(t, []string{tc.want}, got, "%s %s", tc.product, tc.version)
		assert.Equal(t, tc.wantPrecision, precision, "%s %s", tc.product, tc.version)
	}
}

func TestResolveBestEffort_NeverTruncatesToABareMajor(t *testing.T) {
	// This is the rule that keeps the fallback from fabricating inventory.
	//
	// rabbitmq 3.13.7 has no entry at 3.13.7 or 3.13, and at a bare "3" the
	// dictionary carries voxpupuli:rabbitmq — a PUPPET MODULE. influxdb 2.7.12
	// reaches only a bare "2", which is too coarse to mean anything.
	//
	// The repo already names voxpupuli as an anti-goal in
	// test/terraform/aws/recon/technology-emission/outputs.tf, whose comment
	// predicts exactly this: the homonym sibling policy is safe only because
	// homonyms are capped at versions that will not appear in a container tag,
	// and "a resolution rule loosened to reach homonyms would fabricate
	// inventory".
	for _, tc := range []struct{ product, version string }{
		{"rabbitmq", "3.13.7"},
		{"influxdb", "2.7.12"},
	} {
		got, precision := cpe.ResolveBestEffort(tc.product, tc.version)
		assert.Empty(t, got, "%s %s must not reach a bare major", tc.product, tc.version)
		assert.Empty(t, precision)
	}

	// Proof the bare major is what was being avoided, not that these products
	// are simply absent: both DO resolve at one component, and one of them
	// resolves to a vendor this repo forbids.
	assert.NotEmpty(t, cpe.Resolve("rabbitmq", "3"))
	assert.NotEmpty(t, cpe.Resolve("influxdb", "2"))
}

func TestResolveBestEffort_AcceptsAnObservedShortVersionWithoutWalking(t *testing.T) {
	// The floor restricts TRUNCATION, not observation. A version that arrives
	// with one or two components is tried as given — this is what tier 1 and
	// tier 2 already emit, and the fallback must not narrow them.
	got, precision := cpe.ResolveBestEffort("postgresql", "15")
	assert.Equal(t, []string{"cpe:2.3:a:postgresql:postgresql:15:*:*:*:*:*:*:*"}, got)
	assert.Equal(t, "15", precision)

	got, precision = cpe.ResolveBestEffort("postgresql", "15.4")
	assert.Equal(t, []string{"cpe:2.3:a:postgresql:postgresql:15.4:*:*:*:*:*:*:*"}, got)
	assert.Equal(t, "15.4", precision)

	// But a two-component version that does not resolve is not walked down to
	// one. postgres:15.20 from a config marker emits nothing; the image TAG
	// path still supplies "15" independently.
	got, precision = cpe.ResolveBestEffort("postgresql", "15.20")
	assert.Empty(t, got)
	assert.Empty(t, precision)
}

func TestResolveBestEffort_EmitsEverySiblingVendorAtTheResolvedVersion(t *testing.T) {
	// The 2026-11-23 decision — emit both, alias neither — survives the
	// fallback. redis 6.2.6 resolves exactly and carries two live vendors.
	got, precision := cpe.ResolveBestEffort("redis", "6.2.6")
	assert.Equal(t, "6.2.6", precision)
	assert.ElementsMatch(t, []string{
		"cpe:2.3:a:redis:redis:6.2.6:*:*:*:*:*:*:*",
		"cpe:2.3:a:redislabs:redis:6.2.6:*:*:*:*:*:*:*",
	}, got)
}

func TestResolveBestEffort_RejectsUnusableInput(t *testing.T) {
	for _, tc := range []struct{ product, version string }{
		{"", "1.2.3"},
		{"nginx", ""},
		{"", ""},
		{"not_a_real_product_anywhere", "1.2.3"},
	} {
		got, precision := cpe.ResolveBestEffort(tc.product, tc.version)
		assert.Empty(t, got, "%q %q", tc.product, tc.version)
		assert.Empty(t, precision, "%q %q", tc.product, tc.version)
	}
}
