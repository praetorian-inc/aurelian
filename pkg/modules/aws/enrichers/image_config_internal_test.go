package enrichers

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/software/imageconfig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withFetcher swaps the package-level fetcher for one backed by env. The
// registry transport is the only thing faked; the real one is exercised
// against live ECR and live Docker Hub by the AWS integration test.
func withFetcher(t *testing.T, env map[string][]string, err error) *int {
	t.Helper()
	original := imageConfigFetcher
	t.Cleanup(func() { imageConfigFetcher = original })

	var mu sync.Mutex
	calls := 0
	imageConfigFetcher = imageconfig.New(func(_ context.Context, ref string, _ authn.Authenticator) (*v1.ConfigFile, string, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		if err != nil {
			return nil, "", err
		}
		e, ok := env[ref]
		if !ok {
			return nil, "", errors.New("not found")
		}
		return &v1.ConfigFile{Config: v1.Config{Env: e}}, "sha256:" + ref, nil
	})
	return &calls
}

func taskDef(images ...string) *output.AWSResource {
	containers := make([]any, 0, len(images))
	for _, img := range images {
		containers = append(containers, map[string]any{"Image": img})
	}
	return &output.AWSResource{
		ResourceType: "AWS::ECS::TaskDefinition",
		ResourceID:   "task",
		Properties:   map[string]any{"ContainerDefinitions": containers},
	}
}

func cpeSet(r *output.AWSResource) []string {
	out := make([]string, 0, len(r.Technologies))
	for _, t := range r.Technologies {
		out = append(out, t.CPE)
	}
	return out
}

func TestEnrichTechnologies_ReadsTheConfigOfAPrivateImage(t *testing.T) {
	// The phase's reason to exist: a private image whose tag says nothing,
	// identified from the marker its base image left in the environment.
	calls := withFetcher(t, map[string][]string{"myorg/app:v1": {"PYTHON_VERSION=3.11.18"}}, nil)

	r := taskDef("myorg/app:v1")
	cfg := plugin.EnricherConfig{Context: t.Context()}
	require.NoError(t, enrichTechnologies(cfg, r))

	assert.Equal(t, 1, *calls)
	// The observed version, verbatim. Never rewritten to find a dictionary
	// entry — NVD matches CVEs on version ranges, so a version the dictionary
	// does not list still matches, and rewriting it only loses precision.
	assert.Contains(t, cpeSet(r), "cpe:2.3:a:python:python:3.11.18:*:*:*:*:*:*:*")
	for _, tech := range r.Technologies {
		assert.Equal(t, "image-config-env", tech.Source)
		assert.Contains(t, tech.CPE, ":3.11.18:")
	}
}

func TestEnrichTechnologies_TagAndConfigAgreeingIsOneTechnology(t *testing.T) {
	// nginx:1.25.5 yields f5:nginx:1.25.5 from the tag AND from the marker.
	// Emitting it twice would double every finding guard derives from it.
	withFetcher(t, map[string][]string{"nginx:1.25.5": {"NGINX_VERSION=1.25.5"}}, nil)

	r := taskDef("nginx:1.25.5")
	cfg := plugin.EnricherConfig{Context: t.Context()}
	require.NoError(t, enrichTechnologies(cfg, r))

	assert.Equal(t, []string{
		"cpe:2.3:a:f5:nginx:1.25.5:*:*:*:*:*:*:*",
		"cpe:2.3:a:nginx:nginx:1.25.5:*:*:*:*:*:*:*",
	}, cpeSet(r),
		"each CPE appears once, though the tag and the marker both produced it")
	assert.Equal(t, "ecs-image-tag", r.Technologies[0].Source,
		"the tag observed it first; its provenance is the more precise one")
}

func TestEnrichTechnologies_ConfigAddsToWhatTheTagFound(t *testing.T) {
	// tomcat:10's tag gives Tomcat. Its config also gives the JDK underneath,
	// which no tag could have revealed.
	withFetcher(t, map[string][]string{"tomcat:10.1.62": {"TOMCAT_VERSION=10.1.62", "JAVA_VERSION=jdk-25.0.5.1+2"}}, nil)

	r := taskDef("tomcat:10.1.62")
	cfg := plugin.EnricherConfig{Context: t.Context()}
	require.NoError(t, enrichTechnologies(cfg, r))

	assert.Subset(t, cpeSet(r), []string{
		"cpe:2.3:a:apache:tomcat:10.1.62:*:*:*:*:*:*:*",
		"cpe:2.3:a:oracle:openjdk:25.0.5.1:*:*:*:*:*:*:*",
	})
}

func TestEnrichTechnologies_UnreachableRegistryKeepsWhatTheTagFound(t *testing.T) {
	// Fail soft. A denied pull must never cost the emission the tag already
	// earned, and must never fail the enricher.
	withFetcher(t, nil, errors.New("denied"))

	r := taskDef("nginx:1.25.5")
	cfg := plugin.EnricherConfig{Context: t.Context()}
	require.NoError(t, enrichTechnologies(cfg, r))

	assert.Equal(t, []string{
		"cpe:2.3:a:f5:nginx:1.25.5:*:*:*:*:*:*:*",
		"cpe:2.3:a:nginx:nginx:1.25.5:*:*:*:*:*:*:*",
	}, cpeSet(r))
}

func TestEnrichTechnologies_RunningTwiceDoesNotDoubleTheField(t *testing.T) {
	withFetcher(t, map[string][]string{"tomcat:10.1.62": {"JAVA_VERSION=jdk-25.0.5.1+2"}}, nil)

	r := taskDef("tomcat:10.1.62")
	cfg := plugin.EnricherConfig{Context: t.Context()}
	require.NoError(t, enrichTechnologies(cfg, r))
	first := cpeSet(r)
	require.NoError(t, enrichTechnologies(cfg, r))

	assert.Equal(t, first, cpeSet(r))
}

func TestEnrichTechnologies_OneImageAcrossManyResourcesIsFetchedOnce(t *testing.T) {
	// Fifty task definitions on one image are one fetch. The enricher runs
	// inside the shared concurrent pipeline stage, so this also has to hold
	// when those resources are enriched in parallel.
	calls := withFetcher(t, map[string][]string{"myorg/app:v1": {"RUBY_VERSION=3.3.14"}}, nil)
	cfg := plugin.EnricherConfig{Context: t.Context()}

	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			_ = enrichTechnologies(cfg, taskDef("myorg/app:v1"))
		})
	}
	wg.Wait()

	assert.Equal(t, 1, *calls)
}

func TestEnrichTechnologies_ResourcesWithNoImageMakeNoCall(t *testing.T) {
	calls := withFetcher(t, map[string][]string{}, nil)
	cfg := plugin.EnricherConfig{Context: t.Context()}

	r := &output.AWSResource{
		ResourceType: "AWS::RDS::DBInstance",
		Properties:   map[string]any{"Engine": "postgres", "EngineVersion": "15.4"},
	}
	require.NoError(t, enrichTechnologies(cfg, r))

	assert.Zero(t, *calls)
	assert.Contains(t, cpeSet(r), "cpe:2.3:a:postgresql:postgresql:15.4:*:*:*:*:*:*:*")
}
