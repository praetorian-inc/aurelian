package software

import (
	"sort"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/cpe"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/software/imageconfig"
)

// markerProducts maps an image config environment variable to the product NVD
// indexes. Every row was observed in a real config blob — see
// pkg/software/testdata/imageconfig/FINDINGS.md, which records the image each
// one came from and whether it resolves today.
//
// This is an allowlist, deliberately, and not a `*_VERSION` sweep. The same
// harvest found GOSU_VERSION, NJS_VERSION, YARN_VERSION, MYSQL_SHELL_VERSION,
// JSYAML_VERSION and INFLUX_CLI_VERSION sitting beside real markers, plus a
// bare empty `VERSION=` on hashicorp/vault. A sweep would emit a setuid
// helper, a JS YAML library and a CLI as though they were the stack.
//
// Deliberately absent, for the same reason as in image.go: OS base images.
// CPE files operating systems under part `o` and the generator keeps only part
// `a`, so an OS name either has no entry or collides with unrelated
// application software — the `a`-part `alpine` is an email client. Before
// adding a row, confirm what the `a`-part dictionary calls the product.
var markerProducts = map[string]string{
	"NGINX_VERSION":     "nginx",
	"HTTPD_VERSION":     "http_server",
	"HAPROXY_VERSION":   "haproxy",
	"TOMCAT_VERSION":    "tomcat",
	"JETTY_VERSION":     "jetty",
	"RUBY_VERSION":      "ruby",
	"PHP_VERSION":       "php",
	"GOLANG_VERSION":    "go",
	"DOTNET_VERSION":    ".net",
	"PYTHON_VERSION":    "python",
	"NODE_VERSION":      "node.js",
	"REDIS_VERSION":     "redis",
	"MEMCACHED_VERSION": "memcached",
	"MONGO_VERSION":     "mongodb",
	"MYSQL_VERSION":     "mysql",
	"MARIADB_VERSION":   "mariadb",
	"PG_VERSION":        "postgresql",
	"POSTGRES_VERSION":  "postgresql",
	"RABBITMQ_VERSION":  "rabbitmq",
	"INFLUXDB_VERSION":  "influxdb",
	"JENKINS_VERSION":   "jenkins",
	"JAVA_VERSION":      "openjdk",
}

// TechnologiesFromImageConfig returns the technologies identifiable from an
// image's config blob — the software the container exists to run, and the
// language runtime beneath it.
//
// Pure: it takes a value and performs no I/O. The registry fetch that produces
// that value lives in pkg/software/imageconfig and is called from an enricher,
// which is what keeps Detect and everything under it a pure function.
//
// A config carrying no recognised marker yields nothing. That is the designed
// degradation, not a failure: most private images have no marker, the fetch
// costs the same either way, and the image tag path still applies to them.
func TechnologiesFromImageConfig(cfg imageconfig.Config) []output.Technology {
	return resolveFindings(stackFindings(cfg))
}

// stackFindings extracts one finding per recognised marker.
//
// Several markers on one image is the normal case, not an edge: tomcat:10
// carries both TOMCAT_VERSION and JAVA_VERSION, and Java is as much the stack
// as Tomcat is. Nothing here suppresses a marker.
func stackFindings(cfg imageconfig.Config) []finding {
	if len(cfg.Env) == 0 {
		return nil
	}

	// The command the image runs, used only to order the output: the marker
	// naming the entrypoint process comes first, the runtime beneath it after.
	// It is a weak signal by design — tomcat's command is `catalina.sh run`,
	// which names neither marker — so a marker that does not match simply
	// sorts by product name rather than being dropped.
	command := strings.ToLower(strings.Join(append(append([]string{}, cfg.Entrypoint...), cfg.Cmd...), " "))

	var out []finding
	for _, entry := range cfg.Env {
		key, raw, found := strings.Cut(entry, "=")
		if !found {
			continue
		}
		product, ok := markerProducts[strings.ToUpper(strings.TrimSpace(key))]
		if !ok {
			continue
		}
		version := cpe.NormalizeVersion(raw)
		if version == "" {
			continue
		}

		out = append(out, finding{
			product:    product,
			version:    version,
			source:     "image-config-env",
			evidence:   strings.TrimSpace("image " + cfg.Ref + " " + entry),
			bestEffort: true,
			primary:    markerNamesTheCommand(key, command),
		})
	}

	// Deterministic: map iteration order must never reach the output.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].primary != out[j].primary {
			return out[i].primary
		}
		return out[i].product < out[j].product
	})
	return out
}

// markerNamesTheCommand reports whether the marker's subject appears in the
// image's entrypoint or command — PYTHON_VERSION against `python3`,
// MONGO_VERSION against `mongod`, NGINX_VERSION against `nginx -g daemon off`.
func markerNamesTheCommand(key, command string) bool {
	token := strings.ToLower(strings.TrimSuffix(strings.ToUpper(key), "_VERSION"))
	return token != "" && command != "" && strings.Contains(command, token)
}
