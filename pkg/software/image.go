package software

import (
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/cpe"
)

// imageProducts maps an image's base name to the product NVD indexes. The
// names are the ones official images use, which differ from the dictionary's:
// the `postgres` image carries PostgreSQL, the `node` image Node.js, the
// `httpd` image Apache HTTP Server.
//
// An unlisted base name yields nothing. This is where scope is enforced:
// `myorg/internal-app` is not CPE-identifiable software and emitting a guess
// for it would be the confidently-wrong output the design forbids.
var imageProducts = map[string]string{
	"nginx":         "nginx",
	"postgres":      "postgresql",
	"postgresql":    "postgresql",
	"mysql":         "mysql",
	"mariadb":       "mariadb",
	"redis":         "redis",
	"memcached":     "memcached",
	"node":          "node.js",
	"httpd":         "http_server",
	"haproxy":       "haproxy",
	"tomcat":        "tomcat",
	"python":        "python",
	"ruby":          "ruby",
	"php":           "php",
	"golang":        "go",
	"openjdk":       "openjdk",
	"elasticsearch": "elasticsearch",
	"opensearch":    "opensearch",
	"kafka":         "kafka",
	"mongo":         "mongodb",
	"rabbitmq":      "rabbitmq",
	"consul":        "consul",
	"vault":         "vault",
	"traefik":       "traefik",
	"grafana":       "grafana",
	"influxdb":      "influxdb",
	"alpine":        "alpine",
	"debian":        "debian_linux",
	"ubuntu":        "ubuntu_linux",
}

// ParseImageRef parses a `[registry[:port]/][namespace/]name[:tag][@digest]`
// image reference.
//
// An empty product means the reference is unrecognised — either the base name
// maps to no known product or the tag carries no parseable version.
// `nginx:1.25.3-alpine` yields a technology; `app:latest` yields nothing.
//
// The digest, when present, is returned even if nothing else is: it is retained
// in Evidence and feeds tier 3's dedup cache, which keys on digest because
// component content is a pure function of it.
func ParseImageRef(ref string) (product, version, digest string) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", "", ""
	}

	// The digest comes off first; everything after '@' is the digest.
	if name, d, found := strings.Cut(ref, "@"); found {
		ref, digest = name, d
	}

	// Only the last path segment can carry a tag, so a registry port
	// (registry.io:5000/ns/nginx:1.2.3) is never read as one.
	lastSlash := strings.LastIndex(ref, "/")
	segment := ref[lastSlash+1:]

	name, tag := segment, ""
	if i := strings.LastIndex(segment, ":"); i >= 0 {
		name, tag = segment[:i], segment[i+1:]
	}

	product, ok := imageProducts[strings.ToLower(name)]
	if !ok {
		return "", "", digest
	}
	version = cpe.NormalizeVersion(tag)
	if version == "" {
		return "", "", digest
	}
	return product, version, digest
}

// ecsImages walks ContainerDefinitions[].Image. The traversal mirrors
// ecsEnvLines (pkg/aws/extraction/extract_ecs.go:42), which walks the same
// list; missing or mistyped fields are skipped rather than treated as errors.
func ecsImages(props map[string]any) []finding {
	containers, ok := props["ContainerDefinitions"].([]any)
	if !ok {
		return nil
	}

	var out []finding
	for _, c := range containers {
		container, ok := c.(map[string]any)
		if !ok {
			continue
		}
		ref, ok := stringProp(container, "Image")
		if !ok {
			continue
		}
		out = append(out, imageFinding(ref, "ecs-image-tag"))
	}
	return out
}

// lambdaImageURI reads Code.ImageUri, which is only meaningful when
// PackageType is Image.
func lambdaImageURI(props map[string]any) []finding {
	if pt, ok := stringProp(props, "PackageType"); !ok || !strings.EqualFold(pt, "Image") {
		return nil
	}
	code, ok := props["Code"].(map[string]any)
	if !ok {
		return nil
	}
	ref, ok := stringProp(code, "ImageUri")
	if !ok {
		return nil
	}
	return []finding{imageFinding(ref, "lambda-image-uri")}
}

func imageFinding(ref, source string) finding {
	product, version, digest := ParseImageRef(ref)
	evidence := "image " + ref
	if digest != "" && !strings.Contains(ref, digest) {
		evidence += " (" + digest + ")"
	}
	return finding{
		product:  product,
		version:  version,
		source:   source,
		evidence: evidence,
	}
}
