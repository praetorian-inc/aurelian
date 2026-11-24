package software_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/software"
	"github.com/praetorian-inc/aurelian/pkg/software/imageconfig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The env and command values below were read off real image configs pulled
// from live registries on 2026-11-24, verbatim. They are the evidence for the
// 22-row marker allowlist in imagestack.go — written from observation, never
// from memory — and they used to live as 32 JSON files under testdata.
//
// `want` is product@version, not CPE strings: marker extraction owns the
// product and the version, while the vendor fan-out belongs to pkg/cpe and
// changes whenever the NVD table is regenerated.
type imageCase struct {
	env  []string
	cmd  []string // entrypoint followed by cmd, which is all the decoder joins
	want []string
}

// markerImages carry a recognised marker. Only *VERSION* entries are kept —
// PATH, LANG and the rest are inert for this decoder — and the junk variables
// that sit beside a real marker are kept deliberately, because they are what
// makes the allowlist an allowlist rather than a *_VERSION sweep.
var markerImages = map[string]imageCase{
	// jdk- distribution prefix
	"registry-1.docker.io/library/eclipse-temurin:17-jre": {
		env:  []string{"JAVA_VERSION=jdk-17.0.21.1+2"},
		cmd:  []string{"/__cacert_entrypoint.sh"},
		want: []string{"openjdk@17.0.21.1"},
	},
	"registry-1.docker.io/library/golang:1.23": {
		env:  []string{"GOLANG_VERSION=1.23.12"},
		cmd:  []string{"bash"},
		want: []string{"go@1.23.12"},
	},
	"registry-1.docker.io/library/haproxy:2.9": {
		env:  []string{"HAPROXY_VERSION=2.9.15"},
		cmd:  []string{"docker-entrypoint.sh", "haproxy", "-f", "/usr/local/etc/haproxy/haproxy.cfg"},
		want: []string{"haproxy@2.9.15"},
	},
	"registry-1.docker.io/library/httpd:2.4": {
		env:  []string{"HTTPD_VERSION=2.4.71"},
		cmd:  []string{"httpd-foreground"},
		want: []string{"http_server@2.4.71"},
	},
	// INFLUX_CLI_VERSION is the CLI, not the server
	"registry-1.docker.io/library/influxdb:2.7": {
		env:  []string{"INFLUXDB_VERSION=2.7.12", "INFLUX_CLI_VERSION=2.7.5"},
		cmd:  []string{"/entrypoint.sh", "influxd"},
		want: []string{"influxdb@2.7.12"},
	},
	"registry-1.docker.io/jenkins/jenkins:lts": {
		env:  []string{"JENKINS_VERSION=2.580.2"},
		cmd:  []string{"/usr/bin/tini", "--", "/usr/local/bin/jenkins.sh"},
		want: []string{"jenkins@2.580.2"},
	},
	// product name containing a dot
	"public.ecr.aws/lambda/dotnet:8": {
		env:  []string{"DOTNET_VERSION=8.0.34"},
		cmd:  []string{"/lambda-entrypoint.sh"},
		want: []string{".net@8.0.34"},
	},
	// Debian epoch `1:`
	"registry-1.docker.io/library/mariadb:11": {
		env:  []string{"GOSU_VERSION=1.19", "MARIADB_VERSION=1:11.8.9+maria~ubu2404"},
		cmd:  []string{"docker-entrypoint.sh", "mariadbd"},
		want: []string{"mariadb@11.8.9"},
	},
	"registry-1.docker.io/library/memcached:1.6": {
		env:  []string{"MEMCACHED_VERSION=1.6.45"},
		cmd:  []string{"docker-entrypoint.sh", "memcached"},
		want: []string{"memcached@1.6.45"},
	},
	// GOSU_VERSION is a setuid helper, JSYAML a bundled JS library
	"registry-1.docker.io/library/mongo:7": {
		env:  []string{"GOSU_VERSION=1.19", "JSYAML_VERSION=3.13.1", "MONGO_VERSION=7.0.48"},
		cmd:  []string{"docker-entrypoint.sh", "mongod"},
		want: []string{"mongodb@7.0.48"},
	},
	// RPM release suffix
	"registry-1.docker.io/library/mysql:8": {
		env:  []string{"GOSU_VERSION=1.19", "MYSQL_VERSION=8.4.13.1-1.el9", "MYSQL_SHELL_VERSION=8.4.10-1.el9"},
		cmd:  []string{"docker-entrypoint.sh", "mysqld"},
		want: []string{"mysql@8.4.13.1"},
	},
	// NJS_VERSION beside it is the scripting module
	"registry-1.docker.io/library/nginx:1.25": {
		env:  []string{"NGINX_VERSION=1.25.5", "NJS_VERSION=0.8.4"},
		cmd:  []string{"/docker-entrypoint.sh", "nginx", "-g", "daemon off;"},
		want: []string{"nginx@1.25.5"},
	},
	// YARN_VERSION is the package manager
	"registry-1.docker.io/library/node:20-alpine": {
		env:  []string{"NODE_VERSION=20.20.2", "YARN_VERSION=1.22.22"},
		cmd:  []string{"docker-entrypoint.sh", "node"},
		want: []string{"node.js@20.20.2"},
	},
	"registry-1.docker.io/library/php:8.3-apache": {
		env:  []string{"PHP_VERSION=8.3.37"},
		cmd:  []string{"docker-php-entrypoint", "apache2-foreground"},
		want: []string{"php@8.3.37"},
	},
	// pgdg suffix
	"registry-1.docker.io/library/postgres:15": {
		env:  []string{"GOSU_VERSION=1.20", "PG_VERSION=15.20-1.pgdg13+1"},
		cmd:  []string{"docker-entrypoint.sh", "postgres"},
		want: []string{"postgresql@15.20"},
	},
	"registry-1.docker.io/library/python:3.11-slim": {
		env:  []string{"PYTHON_VERSION=3.11.18"},
		cmd:  []string{"python3"},
		want: []string{"python@3.11.18"},
	},
	"registry-1.docker.io/library/rabbitmq:3.13": {
		env:  []string{"RABBITMQ_VERSION=3.13.7"},
		cmd:  []string{"docker-entrypoint.sh", "rabbitmq-server"},
		want: []string{"rabbitmq@3.13.7"},
	},
	"registry-1.docker.io/library/redis:7": {
		env:  []string{"REDIS_VERSION=7.4.12"},
		cmd:  []string{"docker-entrypoint.sh", "redis-server"},
		want: []string{"redis@7.4.12"},
	},
	"registry-1.docker.io/library/ruby:3.3": {
		env:  []string{"RUBY_VERSION=3.3.14"},
		cmd:  []string{"irb"},
		want: []string{"ruby@3.3.14"},
	},
	// two markers: the server and the JDK beneath it
	"registry-1.docker.io/library/tomcat:10": {
		env:  []string{"JAVA_VERSION=jdk-25.0.5.1+2", "TOMCAT_VERSION=10.1.62"},
		cmd:  []string{"catalina.sh", "run"},
		want: []string{"openjdk@25.0.5.1", "tomcat@10.1.62"},
	},
	// ships a bare `VERSION=`
	"registry-1.docker.io/hashicorp/vault:1.16": {
		env:  []string{"VERSION="},
		cmd:  []string{"docker-entrypoint.sh", "server", "-dev"},
		want: []string{},
	},
	// tier 2 cannot name this image; PHP is inherited from its base
	"registry-1.docker.io/library/wordpress:6-php8.2-apache": {
		env:  []string{"PHP_VERSION=8.2.31"},
		cmd:  []string{"docker-entrypoint.sh", "apache2-foreground"},
		want: []string{"php@8.2.31"},
	}}

// noMarkerImages carry nothing the allowlist recognises. They are the
// false-positive control: 22 marker keys matched greedily against every env
// var in existence would fire somewhere, and these are the real images
// proving they do not. A config with no marker yields nothing and falls back
// to tier 2's tag parsing, which is the designed degradation.
var noMarkerImages = []string{
	"registry-1.docker.io/library/consul:1.15",
	"registry-1.docker.io/grafana/grafana:11.0.0",
	"registry-1.docker.io/confluentinc/cp-kafka:7.6.0",
	"registry-1.docker.io/opensearchproject/opensearch:2.13.0",
	"registry-1.docker.io/library/traefik:v3.0",
	"public.ecr.aws/lambda/go:1",
	"public.ecr.aws/lambda/java:21",
	"public.ecr.aws/lambda/nodejs:20",
	"public.ecr.aws/lambda/python:3.12",
	"public.ecr.aws/lambda/ruby:3.3",
}

func TestTechnologiesFromImageConfig_RealImages(t *testing.T) {
	for ref, tc := range markerImages {
		t.Run(ref, func(t *testing.T) {
			got := software.TechnologiesFromImageConfig(
				imageconfig.Config{Ref: ref, Env: tc.env, Cmd: tc.cmd})
			assert.Equal(t, tc.want, productVersionsOf(got))
			for _, tech := range got {
				assert.Equal(t, "image-config-env", tech.Source)
				assert.Contains(t, tech.Evidence, ref)
			}
		})
	}
}

// Only lambda/dotnet among the AWS base images carries a marker, which is why
// image-packaged functions still need tier 2's runtime parsing.
func TestTechnologiesFromImageConfig_ImagesWithNoMarkerYieldNothing(t *testing.T) {
	for _, ref := range noMarkerImages {
		assert.Empty(t, software.TechnologiesFromImageConfig(
			imageconfig.Config{Ref: ref, Env: []string{"PATH=/usr/bin", "LANG=C.UTF-8"}}), ref)
	}
}

// wordpress is why tier 3 exists: its base name is not in tier 2's table, so
// the tag identifies nothing, yet its config carries PHP_VERSION inherited
// from the php base. Every private image built FROM an official one is shaped
// this way.
func TestTechnologiesFromImageConfig_TheTagCannotIdentifyADerivedImage(t *testing.T) {
	product, _, _ := software.ParseImageRef("wordpress:6-php8.2-apache")
	require.Empty(t, product)
	assert.Equal(t, []string{"php@8.2.31"}, productVersionsOf(
		software.TechnologiesFromImageConfig(imageconfig.Config{
			Ref: "wordpress:6-php8.2-apache", Env: []string{"PHP_VERSION=8.2.31"}})))
}

func TestTechnologiesFromImageConfig_IsDeterministic(t *testing.T) {
	cfg := imageconfig.Config{
		Ref: "tomcat:10",
		Env: []string{"JAVA_VERSION=jdk-25.0.5.1+2", "TOMCAT_VERSION=10.1.62"},
		Cmd: []string{"catalina.sh", "run"},
	}
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

func cpesOf(techs []output.Technology) []string {
	out := make([]string, 0, len(techs))
	for _, t := range techs {
		out = append(out, t.CPE)
	}
	return out
}

// productVersionsOf reduces emissions to the distinct product@version pairs
// behind them, dropping the vendor fan-out pkg/cpe applies.
func productVersionsOf(techs []output.Technology) []string {
	seen := map[string]struct{}{}
	out := []string{}
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
	slices.Sort(out)
	return out
}
