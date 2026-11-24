package software_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/software"
	"github.com/praetorian-inc/aurelian/pkg/software/imageconfig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// harvested holds every config blob in testdata/imageconfig against the
// product and version the marker in it must yield, as `product@version`.
//
// These are real blobs pulled from live registries, and this table is the
// record of what they contain — the reason the marker allowlist in
// imagestack.go has the rows it has. A decoder checked against hand-written
// env slices would only prove the author guessed right about official images.
//
// Expectations are product@version rather than CPE strings on purpose: marker
// extraction owns the product and the version, while the vendor list belongs
// to pkg/cpe and changes whenever the NVD table is regenerated.
var harvested = map[string][]string{
	"consul":          nil,
	"eclipse-temurin": {"openjdk@17.0.21.1"}, // JAVA_VERSION=jdk-17.0.21.1+2
	"golang":          {"go@1.23.12"},
	"grafana":         nil,
	"haproxy":         {"haproxy@2.9.15"},
	"httpd":           {"http_server@2.4.71"},
	"influxdb":        {"influxdb@2.7.12"},
	"jenkins":         {"jenkins@2.580.2"},
	"kafka":           nil,
	"lambda-dotnet":   {".net@8.0.34"}, // a product name containing a dot
	"lambda-go":       nil,
	"lambda-java":     nil,
	"lambda-nodejs":   nil,
	"lambda-python":   nil,
	"lambda-ruby":     nil,
	"mariadb":         {"mariadb@11.8.9"}, // MARIADB_VERSION=1:11.8.9+maria~ubu2404
	"memcached":       {"memcached@1.6.45"},
	"mongo":           {"mongodb@7.0.48"},
	"mysql":           {"mysql@8.4.13.1"}, // MYSQL_VERSION=8.4.13.1-1.el9
	"nginx":           {"nginx@1.25.5"},
	"node":            {"node.js@20.20.2"},
	"opensearch":      nil,
	"php":             {"php@8.3.37"},
	"postgres":        {"postgresql@15.20"}, // PG_VERSION=15.20-1.pgdg13+1
	"python":          {"python@3.11.18"},
	"rabbitmq":        {"rabbitmq@3.13.7"},
	"redis":           {"redis@7.4.12"},
	"ruby":            {"ruby@3.3.14"},
	"tomcat":          {"openjdk@25.0.5.1", "tomcat@10.1.62"}, // the runtime under the entrypoint
	"traefik":         nil,
	"vault":           nil,            // ships a bare `VERSION=` with nothing after it
	"wordpress":       {"php@8.2.31"}, // inherited from the php base image
}

func TestTechnologiesFromImageConfig_EveryHarvestedImage(t *testing.T) {
	for slug, want := range harvested {
		t.Run(slug, func(t *testing.T) {
			got := software.TechnologiesFromImageConfig(loadHarvested(t, slug))
			assert.Equal(t, want, productVersionsOf(got))
			for _, tech := range got {
				assert.Equal(t, "image-config-env", tech.Source)
			}
		})
	}
}

// Every blob on disk must appear in the table above, or a fixture can rot
// unnoticed — or be added without anyone recording what it proves.
func TestHarvestedTableCoversEveryFixture(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("testdata", "imageconfig", "*.json"))
	require.NoError(t, err)
	require.NotEmpty(t, paths)

	onDisk := make([]string, 0, len(paths))
	for _, p := range paths {
		onDisk = append(onDisk, strings.TrimSuffix(filepath.Base(p), ".json"))
	}
	sort.Strings(onDisk)

	inTable := make([]string, 0, len(harvested))
	for slug := range harvested {
		inTable = append(inTable, slug)
	}
	sort.Strings(inTable)

	assert.Equal(t, onDisk, inTable)
}

// wordpress:6-php8.2-apache is why tier 3 exists: its base name is not in the
// tier-2 table, so the tag yields nothing, yet its config carries PHP_VERSION
// inherited from the php base. Every private image built FROM an official one
// behaves this way.
func TestTechnologiesFromImageConfig_TheTagCannotIdentifyADerivedImage(t *testing.T) {
	product, _, _ := software.ParseImageRef("wordpress:6-php8.2-apache")
	require.Empty(t, product)
	assert.Equal(t, []string{"php@8.2.31"},
		productVersionsOf(software.TechnologiesFromImageConfig(loadHarvested(t, "wordpress"))))
}

// The marker table is an allowlist, not a *_VERSION sweep: each of these ships
// a real marker beside a version variable for something else entirely.
func TestTechnologiesFromImageConfig_IgnoresNonMarkerVersionVariables(t *testing.T) {
	for _, tc := range []struct {
		slug      string
		forbidden []string
	}{
		{"nginx", []string{"njs"}},           // the njs scripting module
		{"mongo", []string{"gosu", "yaml"}},  // the setuid helper, a bundled JS library
		{"node", []string{"yarn"}},           // the package manager
		{"mysql", []string{"gosu", "shell"}}, // the client shell, not the server
		{"influxdb", []string{"cli"}},        // the CLI, not the server
	} {
		for _, c := range cpesOf(software.TechnologiesFromImageConfig(loadHarvested(t, tc.slug))) {
			for _, bad := range tc.forbidden {
				assert.NotContains(t, c, bad, "image %s emitted %s", tc.slug, c)
			}
		}
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
			for _, tech := range software.TechnologiesFromImageConfig(cfg) {
				assert.Regexp(t, `^cpe:2\.3(:[^:]+){11}$`, tech.CPE, "case %q", name)
			}
		}, "case %q", name)
	}
}

func TestTechnologiesFromImageConfig_EvidenceNamesTheImageAndTheMarker(t *testing.T) {
	got := software.TechnologiesFromImageConfig(loadHarvested(t, "nginx"))
	require.NotEmpty(t, got)
	assert.Contains(t, got[0].Evidence, "registry-1.docker.io/library/nginx:1.25")
	assert.Contains(t, got[0].Evidence, "NGINX_VERSION=1.25.5")
}

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

// productVersionsOf reduces emissions to the distinct `product@version` pairs
// behind them, dropping the vendor fan-out pkg/cpe applies.
func productVersionsOf(techs []output.Technology) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, t := range techs {
		parts := strings.SplitN(t.CPE, ":", 7)
		if len(parts) < 7 {
			continue
		}
		pv := parts[4] + "@" + parts[5]
		if _, dup := seen[pv]; dup {
			continue
		}
		seen[pv] = struct{}{}
		out = append(out, pv)
	}
	sort.Strings(out)
	return out
}
