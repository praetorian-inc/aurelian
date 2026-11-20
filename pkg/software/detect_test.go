package software_test

import (
	"regexp"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/software"
	"github.com/stretchr/testify/assert"
)

func TestDetect_ManagedServiceVersions(t *testing.T) {
	for _, tc := range []struct {
		name, resourceType string
		props              map[string]any
		wantCPEs           []string
	}{
		{"rds postgres", "AWS::RDS::DBInstance",
			map[string]any{"Engine": "postgres", "EngineVersion": "15.4"},
			[]string{"cpe:2.3:a:postgresql:postgresql:15.4:*:*:*:*:*:*:*"}},
		{"rds aurora mysql uses the engine version", "AWS::RDS::DBCluster",
			map[string]any{"Engine": "aurora-mysql", "EngineVersion": "8.0.mysql_aurora.3.04.0"},
			[]string{"cpe:2.3:a:oracle:mysql:8.0:*:*:*:*:*:*:*"}},
		{"lambda provided emits nothing", "AWS::Lambda::Function",
			map[string]any{"Runtime": "provided.al2023"}, nil},

		// Minor-only versions: the decoder extracts the right product and
		// version, but no live dictionary entry carries that version and each
		// product has several vendors, so the resolution rule emits nothing.
		// See this task's blocking note — these are the open gap, not bugs.
		{"lambda python is minor-only", "AWS::Lambda::Function",
			map[string]any{"Runtime": "python3.12"}, nil},
		{"eks version is minor-only", "AWS::EKS::Cluster",
			map[string]any{"Version": "1.29"}, nil},
		{"opensearch version is minor-only", "AWS::OpenSearchService::Domain",
			map[string]any{"EngineVersion": "Elasticsearch_7.10"}, nil},
		{"beanstalk version is minor-only", "AWS::ElasticBeanstalk::Environment",
			map[string]any{"SolutionStackName": "64bit Amazon Linux 2 v3.5.9 running Python 3.11"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.ElementsMatch(t, tc.wantCPEs, cpeStrings(software.Detect(tc.resourceType, tc.props)))
		})
	}
}

// Patch-level versions do resolve. Without these the suite would only ever
// assert that Detect emits nothing, and a decoder that returned no product at
// all would pass every case above.
func TestDetect_PatchLevelVersionsResolve(t *testing.T) {
	for _, tc := range []struct {
		name, resourceType string
		props              map[string]any
		wantCPEs           []string
	}{
		{"elasticache redis", "AWS::ElastiCache::CacheCluster",
			map[string]any{"Engine": "redis", "EngineVersion": "7.0.5"},
			[]string{"cpe:2.3:a:redis:redis:7.0.5:*:*:*:*:*:*:*"}},
		{"elasticache memcached", "AWS::ElastiCache::CacheCluster",
			map[string]any{"Engine": "memcached", "EngineVersion": "1.6.21"},
			[]string{"cpe:2.3:a:memcached:memcached:1.6.21:*:*:*:*:*:*:*"}},
		{"msk kafka", "AWS::MSK::Cluster",
			map[string]any{"KafkaVersion": "3.6.0"},
			[]string{"cpe:2.3:a:apache:kafka:3.6.0:*:*:*:*:*:*:*"}},
		{"rds mariadb", "AWS::RDS::DBInstance",
			map[string]any{"Engine": "mariadb", "EngineVersion": "10.11.5"},
			[]string{"cpe:2.3:a:mariadb:mariadb:10.11.5:*:*:*:*:*:*:*"}},
		{"rds aurora postgresql", "AWS::RDS::DBCluster",
			map[string]any{"Engine": "aurora-postgresql", "EngineVersion": "15.4"},
			[]string{"cpe:2.3:a:postgresql:postgresql:15.4:*:*:*:*:*:*:*"}},
		{"eks patch version", "AWS::EKS::Cluster",
			map[string]any{"Version": "1.29.0"}, nil}, // kubernetes has 2 vendors, neither carries it
		{"opensearch patch version", "AWS::OpenSearchService::Domain",
			map[string]any{"EngineVersion": "OpenSearch_2.11.0"},
			[]string{"cpe:2.3:a:amazon:opensearch:2.11.0:*:*:*:*:*:*:*"}},
		{"lambda python patch version", "AWS::Lambda::Function",
			map[string]any{"Runtime": "python3.12.1"},
			[]string{"cpe:2.3:a:python:python:3.12.1:*:*:*:*:*:*:*"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.ElementsMatch(t, tc.wantCPEs, cpeStrings(software.Detect(tc.resourceType, tc.props)))
		})
	}
}

func TestDetect_SetsSourceAndEvidence(t *testing.T) {
	techs := software.Detect("AWS::RDS::DBInstance",
		map[string]any{"Engine": "postgres", "EngineVersion": "15.4"})
	assert.Len(t, techs, 1)
	assert.Equal(t, "rds-engine", techs[0].Source)
	assert.Contains(t, techs[0].Evidence, "15.4")
	assert.Contains(t, techs[0].Evidence, "postgres")
	assert.Empty(t, techs[0].Name, "Name is advisory; guard overwrites it on ingest")
}

// The decoders must still extract product and version correctly even where the
// dictionary cannot resolve them — otherwise widening the resolution rule later
// would require rewriting the decoders too.
func TestDetect_DecodesMinorOnlyVersionsCorrectly(t *testing.T) {
	for _, tc := range []struct {
		resourceType             string
		props                    map[string]any
		wantProduct, wantVersion string
	}{
		{"AWS::EKS::Cluster", map[string]any{"Version": "1.29"}, "kubernetes", "1.29"},
		{"AWS::Lambda::Function", map[string]any{"Runtime": "python3.12"}, "python", "3.12"},
		{"AWS::OpenSearchService::Domain",
			map[string]any{"EngineVersion": "Elasticsearch_7.10"}, "elasticsearch", "7.10"},
		{"AWS::ElasticBeanstalk::Environment",
			map[string]any{"SolutionStackName": "64bit Amazon Linux 2 v3.5.9 running Python 3.11"},
			"python", "3.11"},
		{"AWS::Lambda::Function", map[string]any{"Runtime": "nodejs20.x"}, "node.js", "20"},
		{"AWS::Lambda::Function", map[string]any{"Runtime": "java21"}, "openjdk", "21"},
	} {
		p, v := software.DecodeForTest(tc.resourceType, tc.props)
		assert.Equal(t, tc.wantProduct, p, tc.resourceType)
		assert.Equal(t, tc.wantVersion, v, tc.resourceType)
	}
}

func TestDetect_BeanstalkNeverTakesThePlatformVersion(t *testing.T) {
	// v3.5.9 is the platform version, never the product's.
	p, v := software.DecodeForTest("AWS::ElasticBeanstalk::Environment",
		map[string]any{"SolutionStackName": "64bit Amazon Linux 2 v3.5.9 running Python 3.11"})
	assert.Equal(t, "python", p)
	assert.NotEqual(t, "3.5.9", v)
}

func TestDetect_AuroraNeverTakesTheAuroraReleaseNumber(t *testing.T) {
	// 3.04.0 is the Aurora release; 8.0 is the compatible MySQL version NVD
	// indexes.
	_, v := software.DecodeForTest("AWS::RDS::DBCluster",
		map[string]any{"Engine": "aurora-mysql", "EngineVersion": "8.0.mysql_aurora.3.04.0"})
	assert.Equal(t, "8.0", v)
}

func TestDetect_HostileInputs(t *testing.T) {
	assert.Empty(t, software.Detect("AWS::RDS::DBInstance", nil))
	assert.Empty(t, software.Detect("AWS::RDS::DBInstance", map[string]any{}))
	assert.Empty(t, software.Detect("AWS::EKS::Cluster", map[string]any{"Version": 1.29}))
	assert.Empty(t, software.Detect("AWS::RDS::DBInstance",
		map[string]any{"Engine": "postgres", "EngineVersion": map[string]any{"x": 1}}))
	assert.Empty(t, software.Detect("AWS::Unknown::Type", map[string]any{"Version": "1.0"}))
}

func TestDetect_WrongTypedPropertiesNeverPanic(t *testing.T) {
	// CloudControl property values arrive as map[string]any; a version can be
	// a number, nil, a list or a nested map. Every read is a checked assertion.
	hostile := []any{nil, 1.29, 42, true, []any{"1.0"}, map[string]any{"x": 1}, []string{"a"}}
	for _, rt := range tier1Types {
		for _, key := range []string{"Engine", "EngineVersion", "Version", "Runtime",
			"ClusterVersion", "SolutionStackName", "KafkaVersion", "ContainerDefinitions"} {
			for _, v := range hostile {
				assert.NotPanics(t, func() {
					software.Detect(rt, map[string]any{key: v})
				}, "%s %s=%v", rt, key, v)
			}
		}
	}
}

func TestDetect_AgainstHarvestedFixtures(t *testing.T) {
	// For every fixture file from phase 0, Detect must not panic and every CPE
	// it returns must satisfy guard's key regex.
	re := regexp.MustCompile(`^cpe:2\.3(:[^:]+){11}$`)
	forEachFixture(t, func(resourceType string, props map[string]any) {
		for _, tech := range software.Detect(resourceType, props) {
			assert.Regexp(t, re, tech.CPE)
			assert.NotEmpty(t, tech.Source)
		}
	})
}
