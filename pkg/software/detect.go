// Package software turns a cloud resource's type and property bag into the
// CPE-identifiable technologies observable on it.
//
// Detect is pure: no network, no filesystem, no provider SDK types. It is the
// single entry point all three clouds share, so there is one detection table
// and one set of table-driven tests rather than one per cloud.
//
// Aurelian emits inventory only. No CVE lookup happens here; guard resolves
// each CPE to CVEs centrally.
package software

import (
	"fmt"
	"sort"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/cpe"
	"github.com/praetorian-inc/aurelian/pkg/output"
)

// finding is what a decoder extracted from a property bag, before the CPE
// dictionary is consulted. Keeping extraction separate from resolution is what
// lets the decoding logic be tested independently of whether the dictionary can
// resolve the result — see DecodeForTest.
type finding struct {
	product  string
	version  string
	source   string
	evidence string

	// primary marks the software the image's entrypoint runs, as opposed to
	// the runtime beneath it. Ordering only — it never suppresses a finding.
	primary bool
}

// decoder reads one resource type's property bag. It returns one finding per
// piece of software it can see — several, for a task definition with several
// containers.
type decoder func(props map[string]any) []finding

// registry maps a resource type to its decoders. It holds a slice rather than a
// single decoder because one type can carry software in two unrelated places:
// a Lambda function has both a managed runtime and, when PackageType is Image,
// a container image, and each needs its own Source.
var registry = map[string][]decoder{
	"AWS::RDS::DBInstance":               {rdsEngine},
	"AWS::RDS::DBCluster":                {rdsEngine},
	"AWS::Lambda::Function":              {lambdaRuntime, lambdaImageURI},
	"AWS::ECS::TaskDefinition":           {ecsImages},
	"AWS::EKS::Cluster":                  {eksVersion},
	"AWS::OpenSearchService::Domain":     {opensearchEngine},
	"AWS::ElastiCache::CacheCluster":     {elasticacheEngine},
	"AWS::Redshift::Cluster":             {redshiftVersion},
	"AWS::ElasticBeanstalk::Environment": {beanstalkStack},
	"AWS::MSK::Cluster":                  {mskVersion},
}

// Detect returns the technologies identifiable from a resource's type and
// property bag. Pure: no I/O, no network, no provider SDK types.
//
// A property bag that is nil, sparse or wrongly typed yields an empty slice
// rather than a panic: CloudControl ListResources returns a sparse property set
// for some types, and a value the schema calls a string can arrive as a number,
// a nil or a nested map.
//
// Anything that cannot be resolved to a vendor emits nothing. Silence is the
// correct failure mode — a mis-vendored CPE resolves against the wrong CVE set
// and produces a credible-looking lie.
func Detect(resourceType string, props map[string]any) []output.Technology {
	if len(props) == 0 {
		return nil
	}

	var findings []finding
	for _, decode := range registry[resourceType] {
		findings = append(findings, decode(props)...)
	}
	return resolveFindings(findings)
}

// resolveFindings turns extracted findings into technologies. It is shared by
// every decoder — property-bag and image-config alike — so resolution, CPE
// wrapping and provenance are decided in exactly one place.
func resolveFindings(findings []finding) []output.Technology {
	var out []output.Technology
	for _, f := range findings {
		if f.product == "" || f.version == "" {
			continue
		}

		// The observed version is emitted verbatim. It is never rewritten to
		// find a dictionary entry: NVD attaches CVEs to version ranges, so a
		// version absent from the dictionary still matches, and rewriting it
		// attributes CVEs that do not apply.
		for _, c := range cpe.Resolve(f.product, f.version) {
			out = append(out, output.Technology{
				CPE:      c,
				Source:   f.source,
				Evidence: f.evidence,
			})
		}
	}
	return out
}

// decode runs a type's decoders in order and returns the first product and
// version extracted, before resolution. DecodeForTest exports it.
func decode(resourceType string, props map[string]any) (product, version string) {
	for _, d := range registry[resourceType] {
		for _, f := range d(props) {
			if f.product != "" {
				return f.product, f.version
			}
		}
	}
	return "", ""
}

// rdsEngineProducts maps an RDS or ElastiCache Engine value to the product name
// NVD indexes. Aurora variants map to their underlying engine, which is what
// the version describes.
var rdsEngineProducts = map[string]string{
	"postgres":          "postgresql",
	"aurora-postgresql": "postgresql",
	"mysql":             "mysql",
	"aurora-mysql":      "mysql",
	"mariadb":           "mariadb",
	"redis":             "redis",
	"memcached":         "memcached",
}

func rdsEngine(props map[string]any) []finding {
	return engineAndVersion(props, "rds-engine")
}

func elasticacheEngine(props map[string]any) []finding {
	return engineAndVersion(props, "elasticache-engine")
}

// engineAndVersion reads the Engine/EngineVersion pair RDS and ElastiCache
// share. An Aurora EngineVersion like 8.0.mysql_aurora.3.04.0 carries both the
// compatible engine version and the Aurora release; NormalizeVersion's dotted
// numeric prefix takes 8.0, which is what NVD indexes, never 3.04.0.
func engineAndVersion(props map[string]any, source string) []finding {
	engine, ok := stringProp(props, "Engine")
	if !ok {
		return nil
	}
	raw, ok := stringProp(props, "EngineVersion")
	if !ok {
		return nil
	}
	product, ok := rdsEngineProducts[strings.ToLower(engine)]
	if !ok {
		return nil
	}
	return []finding{{
		product:  product,
		version:  cpe.NormalizeVersion(raw),
		source:   source,
		evidence: fmt.Sprintf("Engine=%s EngineVersion=%s", engine, raw),
	}}
}

// lambdaRuntimeProducts maps a Lambda runtime's language prefix to the product
// NVD indexes. `provided.*` runtimes are OS shims with no language version and
// are absent deliberately.
var lambdaRuntimeProducts = map[string]string{
	"python": "python",
	"nodejs": "node.js",
	"java":   "openjdk",
	"dotnet": ".net",
	"ruby":   "ruby",
	"go":     "go",
}

// lambdaRuntime splits a Runtime like python3.12, nodejs20.x, java21 or
// dotnet8 on the first digit: the prefix selects the product and the remainder
// is the version.
func lambdaRuntime(props map[string]any) []finding {
	raw, ok := stringProp(props, "Runtime")
	if !ok {
		return nil
	}

	i := strings.IndexFunc(raw, isDigit)
	if i <= 0 {
		return nil
	}
	product, ok := lambdaRuntimeProducts[strings.ToLower(raw[:i])]
	if !ok {
		return nil
	}
	return []finding{{
		product:  product,
		version:  cpe.NormalizeVersion(raw[i:]),
		source:   "lambda-runtime",
		evidence: "Runtime=" + raw,
	}}
}

func eksVersion(props map[string]any) []finding {
	raw, ok := stringProp(props, "Version")
	if !ok {
		return nil
	}
	return []finding{{
		product:  "kubernetes",
		version:  cpe.NormalizeVersion(raw),
		source:   "eks-version",
		evidence: "Version=" + raw,
	}}
}

// opensearchEngineProducts: the prefix of an OpenSearch EngineVersion selects
// the product, since a domain can run either engine.
var opensearchEngineProducts = map[string]string{
	"opensearch":    "opensearch",
	"elasticsearch": "elasticsearch",
}

// opensearchEngine reads an EngineVersion like OpenSearch_2.11 or
// Elasticsearch_7.10.
func opensearchEngine(props map[string]any) []finding {
	raw, ok := stringProp(props, "EngineVersion")
	if !ok {
		return nil
	}
	prefix, version, found := strings.Cut(raw, "_")
	if !found {
		return nil
	}
	product, ok := opensearchEngineProducts[strings.ToLower(prefix)]
	if !ok {
		return nil
	}
	return []finding{{
		product:  product,
		version:  cpe.NormalizeVersion(version),
		source:   "opensearch-engine",
		evidence: "EngineVersion=" + raw,
	}}
}

// redshiftVersion reads ClusterVersion. NVD carries no `redshift` product
// today, so this resolves to nothing; it is registered so the type is covered
// the moment one appears, and because a decoder that silently does not exist is
// harder to notice than one that emits nothing.
func redshiftVersion(props map[string]any) []finding {
	raw, ok := stringProp(props, "ClusterVersion")
	if !ok {
		return nil
	}
	return []finding{{
		product:  "redshift",
		version:  cpe.NormalizeVersion(raw),
		source:   "redshift-version",
		evidence: "ClusterVersion=" + raw,
	}}
}

func mskVersion(props map[string]any) []finding {
	raw, ok := stringProp(props, "KafkaVersion")
	if !ok {
		return nil
	}
	return []finding{{
		product:  "kafka",
		version:  cpe.NormalizeVersion(raw),
		source:   "msk-version",
		evidence: "KafkaVersion=" + raw,
	}}
}

// beanstalkPlatformProducts maps the platform name a SolutionStackName uses to
// the product NVD indexes.
var beanstalkPlatformProducts = map[string]string{
	"python":  "python",
	"node.js": "node.js",
	"php":     "php",
	"ruby":    "ruby",
	"go":      "go",
	"tomcat":  "tomcat",
	"java":    "openjdk",
}

// beanstalkStack parses a SolutionStackName such as
// "64bit Amazon Linux 2 v3.5.9 running Python 3.11". The version is the one
// following "running <product>", never the v3.5.9 platform version.
func beanstalkStack(props map[string]any) []finding {
	raw, ok := stringProp(props, "SolutionStackName")
	if !ok {
		return nil
	}
	_, after, found := strings.Cut(raw, " running ")
	if !found {
		return nil
	}

	// The platform name is the tokens before the first one starting with a
	// digit, which is its version.
	fields := strings.Fields(after)
	var nameParts []string
	version := ""
	for _, f := range fields {
		if f != "" && isDigit(rune(f[0])) {
			version = f
			break
		}
		nameParts = append(nameParts, f)
	}
	if version == "" || len(nameParts) == 0 {
		return nil
	}

	product, ok := beanstalkPlatformProducts[strings.ToLower(strings.Join(nameParts, " "))]
	if !ok {
		return nil
	}
	return []finding{{
		product:  product,
		version:  cpe.NormalizeVersion(version),
		source:   "beanstalk-stack",
		evidence: "SolutionStackName=" + raw,
	}}
}

// stringProp is the only way this package reads a property. CloudControl
// property values are map[string]any, so a value the schema calls a string can
// arrive as a number, a nil, a list or a nested map; an unchecked assertion
// would panic on real data.
func stringProp(props map[string]any, key string) (string, bool) {
	v, ok := props[key].(string)
	if !ok || v == "" {
		return "", false
	}
	return v, true
}

func isDigit(r rune) bool { return r >= '0' && r <= '9' }

// RegisteredTypes returns the resource types Detect can decode, sorted. It
// exists so a caller can register itself for exactly those types without
// restating the list — a second copy would drift the moment a decoder is added.
func RegisteredTypes() []string {
	out := make([]string, 0, len(registry))
	for rt := range registry {
		out = append(out, rt)
	}
	sort.Strings(out)
	return out
}
