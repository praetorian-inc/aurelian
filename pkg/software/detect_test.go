package software_test

import (
	"regexp"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/software"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// The real tier-1 coverage, pinned against the values AWS actually produces.
//
// A minor-only version is NOT uniformly dropped: it is dropped for a
// multi-vendor product (rule 3) and accepted for a sole-vendor one (rule 2).
// The upshot, which no prose elsewhere should be trusted to state correctly:
// EKS, OpenSearch and Redshift emit nothing for any input AWS produces; Lambda
// emits only for Java/.NET/Ruby, never Python/Node/Go; Beanstalk emits only
// where the platform's product is sole-vendor.
//
// This test exists so that a change to the resolution rule shows up here as a
// diff rather than as a silent change in customer inventory.
func TestDetect_Tier1CoverageAgainstRealAWSValues(t *testing.T) {
	for _, tc := range []struct {
		name, resourceType string
		props              map[string]any
		wantCPEs           []string
	}{
		{"eks always emits nothing", "AWS::EKS::Cluster",
			map[string]any{"Version": "1.29"}, nil},
		{"eks patch emits nothing either", "AWS::EKS::Cluster",
			map[string]any{"Version": "1.29.0"}, nil},
		{"opensearch emits nothing", "AWS::OpenSearchService::Domain",
			map[string]any{"EngineVersion": "OpenSearch_2.11"}, nil},
		{"redshift emits nothing", "AWS::Redshift::Cluster",
			map[string]any{"ClusterVersion": "1.0"}, nil},
		{"lambda python emits nothing", "AWS::Lambda::Function",
			map[string]any{"Runtime": "python3.12"}, nil},
		{"lambda node emits nothing", "AWS::Lambda::Function",
			map[string]any{"Runtime": "nodejs20.x"}, nil},
		{"lambda java emits", "AWS::Lambda::Function",
			map[string]any{"Runtime": "java21"},
			[]string{"cpe:2.3:a:oracle:openjdk:21:*:*:*:*:*:*:*"}},
		{"lambda dotnet emits", "AWS::Lambda::Function",
			map[string]any{"Runtime": "dotnet8"},
			[]string{"cpe:2.3:a:microsoft:.net:8:*:*:*:*:*:*:*"}},
		{"lambda ruby emits", "AWS::Lambda::Function",
			map[string]any{"Runtime": "ruby3.2"},
			[]string{"cpe:2.3:a:ruby-lang:ruby:3.2:*:*:*:*:*:*:*"}},
		{"beanstalk python emits nothing", "AWS::ElasticBeanstalk::Environment",
			map[string]any{"SolutionStackName": "64bit Amazon Linux 2 v3.5.9 running Python 3.11"}, nil},
		{"beanstalk php emits", "AWS::ElasticBeanstalk::Environment",
			map[string]any{"SolutionStackName": "64bit Amazon Linux 2 v3.5.9 running PHP 8.1"},
			[]string{"cpe:2.3:a:php:php:8.1:*:*:*:*:*:*:*"}},
		{"rds emits", "AWS::RDS::DBInstance",
			map[string]any{"Engine": "postgres", "EngineVersion": "15.4"},
			[]string{"cpe:2.3:a:postgresql:postgresql:15.4:*:*:*:*:*:*:*"}},
		{"msk emits", "AWS::MSK::Cluster",
			map[string]any{"KafkaVersion": "3.6.0"},
			[]string{"cpe:2.3:a:apache:kafka:3.6.0:*:*:*:*:*:*:*"}},
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
	//
	// The counts are asserted because this test would otherwise be vacuous and
	// silently so: phase 0's account yielded 13 Lambda property bags whose
	// listing omits Runtime entirely, and one ECS task definition whose only
	// image is `alpine:latest` (no parseable version). Detect therefore returns
	// nothing for all 14, the loop body never runs, and the test would pass
	// just as well if Detect were `return nil`.
	//
	// Pinning the measured zero turns that into a signal: harvest a fixture
	// that does carry a version and this test fails, which is the moment
	// someone should look at what it now emits.
	re := regexp.MustCompile(`^cpe:2\.3(:[^:]+){11}$`)

	bags, techs := 0, 0
	forEachFixture(t, func(resourceType string, props map[string]any) {
		bags++
		for _, tech := range software.Detect(resourceType, props) {
			techs++
			assert.Regexp(t, re, tech.CPE)
			assert.NotEmpty(t, tech.Source)
		}
	})

	assert.Equal(t, 14, bags, "fixture count changed; re-check what Detect now emits")
	assert.Equal(t, 0, techs,
		"phase 0's fixtures carry no usable version; a non-zero count means new "+
			"fixtures were harvested and their output needs reviewing")
}

// The fixtures cannot exercise a successful detection, so the guard's-key-regex
// property is also asserted against property bags shaped like the ones phase 0
// failed to find. Without this, no test asserts that a *fixture-shaped* input
// producing output produces a well-formed one.
func TestDetect_FixtureShapedInputsProduceWellFormedCPEs(t *testing.T) {
	re := regexp.MustCompile(`^cpe:2\.3(:[^:]+){11}$`)

	emitted := 0
	for _, tc := range []struct {
		resourceType string
		props        map[string]any
	}{
		{"AWS::RDS::DBInstance", map[string]any{"Engine": "postgres", "EngineVersion": "15.4"}},
		{"AWS::ElastiCache::CacheCluster", map[string]any{"Engine": "redis", "EngineVersion": "7.0.5"}},
		{"AWS::MSK::Cluster", map[string]any{"KafkaVersion": "3.6.0"}},
		{"AWS::Lambda::Function", map[string]any{"Runtime": "java21"}},
		{"AWS::ECS::TaskDefinition", map[string]any{"ContainerDefinitions": []any{
			map[string]any{"Image": "nginx:1.25.3"},
			map[string]any{"Image": "public.ecr.aws/docker/library/postgres:15.4"},
		}}},
	} {
		for _, tech := range software.Detect(tc.resourceType, tc.props) {
			emitted++
			assert.Regexp(t, re, tech.CPE, tc.resourceType)
			assert.NotEmpty(t, tech.Source, tc.resourceType)
			assert.NotEmpty(t, tech.Evidence, tc.resourceType)
		}
	}
	require.NotZero(t, emitted, "assertions above must actually run")
}
