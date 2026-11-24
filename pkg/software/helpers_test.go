package software_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/stretchr/testify/require"
)

// tier1Types is the set of resource types phase 0 harvested fixtures for. A
// fixture file whose name matches none of them is a mistake, not something to
// skip quietly.
var tier1Types = []string{
	"AWS::RDS::DBInstance",
	"AWS::RDS::DBCluster",
	"AWS::Lambda::Function",
	"AWS::EKS::Cluster",
	"AWS::OpenSearchService::Domain",
	"AWS::ElastiCache::CacheCluster",
	"AWS::Redshift::Cluster",
	"AWS::ElasticBeanstalk::Environment",
	"AWS::MSK::Cluster",
	"AWS::ECS::TaskDefinition",
}

// cpeStrings returns the CPE of each technology, order preserved.
func cpeStrings(techs []output.Technology) []string {
	if len(techs) == 0 {
		return nil
	}
	out := make([]string, 0, len(techs))
	for _, t := range techs {
		out = append(out, t.CPE)
	}
	return out
}

// forEachFixture walks the property bags harvested from a live account in
// phase 0, calling fn once per observed properties object. The resource type
// comes from the filename: the type lowercased with "::" replaced by "_".
func forEachFixture(t *testing.T, fn func(resourceType string, props map[string]any)) {
	t.Helper()

	byFile := make(map[string]string, len(tier1Types))
	for _, rt := range tier1Types {
		byFile[strings.ToLower(strings.ReplaceAll(rt, "::", "_"))+".json"] = rt
	}

	paths, err := filepath.Glob(filepath.Join("testdata", "properties", "aws", "*.json"))
	require.NoError(t, err)
	require.NotEmpty(t, paths, "no harvested fixtures found; phase 0 produces them")

	for _, path := range paths {
		name := filepath.Base(path)
		resourceType, ok := byFile[name]
		require.Truef(t, ok, "fixture %s does not name a known tier-1 resource type", name)

		raw, err := os.ReadFile(path)
		require.NoError(t, err)
		var bags []map[string]any
		require.NoErrorf(t, json.Unmarshal(raw, &bags), "fixture %s", name)

		for _, props := range bags {
			fn(resourceType, props)
		}
	}
}
