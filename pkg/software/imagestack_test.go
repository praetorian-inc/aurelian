package software_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/software"
	"github.com/praetorian-inc/aurelian/pkg/software/imageconfig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loadHarvested reads one of the config blobs harvested from a live registry
// in pkg/software/testdata/imageconfig. These are real blobs, verbatim: a
// decoder tested against hand-written env slices would be tested against what
// the author imagined official images do, which is the mistake FINDINGS.md
// exists to prevent.
func loadHarvested(t *testing.T, slug string) imageconfig.Config {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "imageconfig", slug+".json"))
	require.NoError(t, err, "harvested config %q", slug)

	var doc struct {
		Image  string `json:"image"`
		Digest string `json:"digest"`
		Config struct {
			Config struct {
				Env        []string `json:"Env"`
				Entrypoint []string `json:"Entrypoint"`
				Cmd        []string `json:"Cmd"`
			} `json:"config"`
		} `json:"config"`
	}
	require.NoError(t, json.Unmarshal(raw, &doc))

	return imageconfig.Config{
		Ref:        doc.Image,
		Digest:     doc.Digest,
		Env:        doc.Config.Config.Env,
		Entrypoint: doc.Config.Config.Entrypoint,
		Cmd:        doc.Config.Config.Cmd,
	}
}

func cpesOf(techs []output.Technology) []string {
	out := make([]string, 0, len(techs))
	for _, t := range techs {
		out = append(out, t.CPE)
	}
	return out
}

func TestTechnologiesFromImageConfig_FullPrecisionMarker(t *testing.T) {
	got := software.TechnologiesFromImageConfig(loadHarvested(t, "nginx"))

	require.Len(t, got, 1)
	assert.Equal(t, "cpe:2.3:a:f5:nginx:1.25.5:*:*:*:*:*:*:*", got[0].CPE)
	assert.Equal(t, "image-config-env", got[0].Source)
	assert.Contains(t, got[0].Evidence, "NGINX_VERSION=1.25.5")
}

func TestTechnologiesFromImageConfig_EmitsTheObservedVersionVerbatim(t *testing.T) {
	// python:3.11-slim reports PYTHON_VERSION=3.11.18, which has no CPE
	// dictionary entry. It is emitted anyway, unchanged.
	//
	// An earlier revision truncated it to 3.11 to find a dictionary hit and
	// marked the result "-truncated". Measured against the live NVD CVE
	// corpus on 2026-11-24, that was backwards: 3.11.18 matches 15 CVEs
	// through NVD's version ranges, which do not require a dictionary entry,
	// while the 3.11 emitted in its place matched 10 of those plus 1 that
	// does not apply. Rewriting an observed version can only lose precision.
	got := software.TechnologiesFromImageConfig(loadHarvested(t, "python"))

	assert.Contains(t, cpesOf(got), "cpe:2.3:a:python:python:3.11.18:*:*:*:*:*:*:*")
	for _, tech := range got {
		assert.Equal(t, "image-config-env", tech.Source, "there is no truncated provenance any more")
		assert.Contains(t, tech.CPE, ":3.11.18:", "the observed version is never rewritten")
		assert.Contains(t, tech.Evidence, "PYTHON_VERSION=3.11.18")
	}
}

func TestTechnologiesFromImageConfig_InheritedMarkerOnADerivedImage(t *testing.T) {
	// The reason this phase exists. wordpress:6-php8.2-apache is not a `php`
	// image, its base name is not in the tier-2 table, and ParseImageRef
	// returns nothing for it — yet its config carries PHP_VERSION, inherited
	// from the php base. Every private image built FROM an official one
	// behaves this way.
	assertEmitsNothingFromTheTag(t, "wordpress:6-php8.2-apache")

	got := software.TechnologiesFromImageConfig(loadHarvested(t, "wordpress"))
	assert.Contains(t, cpesOf(got), "cpe:2.3:a:php:php:8.2.31:*:*:*:*:*:*:*")
}

func assertEmitsNothingFromTheTag(t *testing.T, ref string) {
	t.Helper()
	product, _, _ := software.ParseImageRef(ref)
	assert.Empty(t, product, "tier 2 is expected to miss %q; if it no longer does, this test proves less than it claims", ref)
}

func TestTechnologiesFromImageConfig_EmitsTheRuntimeBeneathTheEntrypoint(t *testing.T) {
	// tomcat:10 carries TOMCAT_VERSION and JAVA_VERSION. Tomcat is what the
	// entrypoint runs; Java is what it runs on. Both are the stack, and an
	// ordering rule must not suppress the one that is not the entrypoint.
	got := software.TechnologiesFromImageConfig(loadHarvested(t, "tomcat"))

	// Subset, not an exact set: a product resolves under every vendor the
	// dictionary lists for it, and that list is snapshot data owned by
	// pkg/cpe. What matters here is that BOTH markers produced a technology.
	assert.Subset(t, cpesOf(got), []string{
		"cpe:2.3:a:apache:tomcat:10.1.62:*:*:*:*:*:*:*",
		"cpe:2.3:a:oracle:openjdk:25.0.5.1:*:*:*:*:*:*:*",
	})
}

func TestTechnologiesFromImageConfig_IgnoresNonMarkerVersionVariables(t *testing.T) {
	// The marker table is an allowlist, not a *_VERSION sweep. Each of these
	// images carries a real marker next to junk that must not be emitted.
	for _, tc := range []struct {
		slug      string
		want      []string
		forbidden []string
	}{
		{"nginx", []string{"cpe:2.3:a:f5:nginx:1.25.5:*:*:*:*:*:*:*"}, []string{"njs"}},
		{"mongo", []string{"cpe:2.3:a:mongodb:mongodb:7.0.48:*:*:*:*:*:*:*"}, []string{"gosu", "js-yaml", "jsyaml"}},
		{"node", []string{"cpe:2.3:a:nodejs:node.js:20.20.2:*:*:*:*:*:*:*"}, []string{"yarn"}},
		{"mysql", []string{"cpe:2.3:a:oracle:mysql:8.4.13.1:*:*:*:*:*:*:*"}, []string{"gosu", "shell"}},
	} {
		got := cpesOf(software.TechnologiesFromImageConfig(loadHarvested(t, tc.slug)))
		assert.Subset(t, got, tc.want, "image %s", tc.slug)
		for _, bad := range tc.forbidden {
			for _, c := range got {
				assert.NotContains(t, c, bad, "image %s emitted %s", tc.slug, c)
			}
		}
	}
}

func TestTechnologiesFromImageConfig_HomonymVendorsAreEmittedAndAreInert(t *testing.T) {
	// An earlier revision refused to emit anything for these, because
	// resolving them required truncating to a bare major, and at a bare major
	// rabbitmq reaches voxpupuli — a Puppet module.
	//
	// Measured on 2026-11-24, that defence was aimed at the wrong thing. With
	// the observed version emitted verbatim, voxpupuli:rabbitmq:3.13.7 matches
	// no CVE, because the Puppet module never shipped 3.13.7. The version is
	// the filter, not the vendor. Refusing to emit cost the one CVE that truly
	// affects rabbitmq 3.13.7, and influxdb's entirely.
	for _, tc := range []struct{ slug, want string }{
		{"rabbitmq", "cpe:2.3:a:broadcom:rabbitmq:3.13.7:*:*:*:*:*:*:*"},
		{"influxdb", "cpe:2.3:a:influxdata:influxdb:2.7.12:*:*:*:*:*:*:*"},
	} {
		got := cpesOf(software.TechnologiesFromImageConfig(loadHarvested(t, tc.slug)))
		assert.Contains(t, got, tc.want, "image %s", tc.slug)
		for _, c := range got {
			assert.Contains(t, c, ":"+observedVersionOf(tc.slug)+":",
				"image %s emitted a rewritten version in %s", tc.slug, c)
		}
	}
}

// observedVersionOf is the marker value each harvested image carries, from
// pkg/software/testdata/imageconfig/FINDINGS.md.
func observedVersionOf(slug string) string {
	return map[string]string{"rabbitmq": "3.13.7", "influxdb": "2.7.12"}[slug]
}

func TestTechnologiesFromImageConfig_SurvivesImagesWithNoMarker(t *testing.T) {
	// Most private images, and several official ones, carry nothing usable.
	// That is the designed degradation: the config fetch costs the same either
	// way and tier 2's tag parsing still applies.
	for _, slug := range []string{"traefik", "grafana", "kafka", "opensearch", "consul", "lambda-go", "lambda-python"} {
		assert.Empty(t, software.TechnologiesFromImageConfig(loadHarvested(t, slug)), "image %s", slug)
	}
}

func TestTechnologiesFromImageConfig_IgnoresABareEmptyVersionVariable(t *testing.T) {
	// hashicorp/vault ships a bare `VERSION=` with nothing after it.
	assert.Empty(t, software.TechnologiesFromImageConfig(loadHarvested(t, "vault")))
}

func TestTechnologiesFromImageConfig_NormalisesAwkwardRealValues(t *testing.T) {
	for _, tc := range []struct{ slug, want string }{
		{"eclipse-temurin", "cpe:2.3:a:oracle:openjdk:17.0.21.1:*:*:*:*:*:*:*"}, // JAVA_VERSION=jdk-17.0.21.1+2
		{"mariadb", "cpe:2.3:a:mariadb:mariadb:11.8.9:*:*:*:*:*:*:*"},           // MARIADB_VERSION=1:11.8.9+maria~ubu2404
		{"lambda-dotnet", "cpe:2.3:a:microsoft:.net:8.0.34:*:*:*:*:*:*:*"},      // a product name containing a dot
	} {
		assert.Contains(t, cpesOf(software.TechnologiesFromImageConfig(loadHarvested(t, tc.slug))), tc.want, "image %s", tc.slug)
	}
}

func TestTechnologiesFromImageConfig_IsDeterministic(t *testing.T) {
	cfg := loadHarvested(t, "tomcat")
	first := cpesOf(software.TechnologiesFromImageConfig(cfg))
	for range 20 {
		assert.Equal(t, first, cpesOf(software.TechnologiesFromImageConfig(cfg)),
			"map iteration order must not reach the output")
	}
}

func TestTechnologiesFromImageConfig_HandlesHostileAndMalformedInput(t *testing.T) {
	for name, cfg := range map[string]imageconfig.Config{
		"zero":              {},
		"no env":            {Ref: "app:1", Digest: "sha256:a"},
		"malformed entries": {Env: []string{"", "=", "NOEQUALS", "=novalue", "PYTHON_VERSION="}},
		"marker not a version": {Env: []string{
			"PYTHON_VERSION=latest", "NGINX_VERSION=$(whoami)", "REDIS_VERSION=../../etc/passwd",
		}},
		"colon injection": {Env: []string{"NGINX_VERSION=1.25.5:extra:fields"}},
		"wildcard injection": {Env: []string{
			"NGINX_VERSION=*", "PHP_VERSION=?", `RUBY_VERSION=3.3.14\:*\:*`,
		}},
		"huge value": {Env: []string{"PYTHON_VERSION=" + strings.Repeat("9", 100_000)}},
	} {
		assert.NotPanics(t, func() {
			got := software.TechnologiesFromImageConfig(cfg)
			for _, tech := range got {
				assert.Regexp(t, `^cpe:2\.3(:[^:]+){11}$`, tech.CPE, "case %q", name)
			}
		}, "case %q", name)
	}
}

func TestTechnologiesFromImageConfig_EvidenceNamesTheImage(t *testing.T) {
	got := software.TechnologiesFromImageConfig(loadHarvested(t, "nginx"))
	require.NotEmpty(t, got)
	assert.Contains(t, got[0].Evidence, "registry-1.docker.io/library/nginx:1.25",
		"evidence must say which image the marker came from")
}
