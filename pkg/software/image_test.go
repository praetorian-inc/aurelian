package software_test

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/software"
	"github.com/stretchr/testify/assert"
)

func TestParseImageRef(t *testing.T) {
	for _, tc := range []struct {
		in                                   string
		wantProduct, wantVersion, wantDigest string
	}{
		{"nginx:1.25.3-alpine", "nginx", "1.25.3", ""},
		{"public.ecr.aws/docker/library/postgres:15.4", "postgresql", "15.4", ""},
		{"registry.io:5000/ns/nginx:1.2.3", "nginx", "1.2.3", ""},
		{"nginx:1.2.3@sha256:abc", "nginx", "1.2.3", "sha256:abc"},
		{"app:latest", "", "", ""},
		{"nginx", "", "", ""},
		{"myorg/internal-app:2.1", "", "", ""},
	} {
		p, v, d := software.ParseImageRef(tc.in)
		assert.Equal(t, tc.wantProduct, p, "input %q", tc.in)
		assert.Equal(t, tc.wantVersion, v, "input %q", tc.in)
		assert.Equal(t, tc.wantDigest, d, "input %q", tc.in)
	}
}

func TestParseImageRef_HostileRefs(t *testing.T) {
	// Nothing here should panic or invent a product.
	for _, in := range []string{
		"", ":", "@", ":@", "nginx:", ":1.2.3", "/", "///",
		"registry.io:5000/nginx", // no tag, only a registry port
		"nginx@sha256:abc",       // digest only, no tag
		"nginx:stable",
		"nginx:latest@sha256:abc",
	} {
		p, v, _ := software.ParseImageRef(in)
		assert.Empty(t, p, "input %q", in)
		assert.Empty(t, v, "input %q", in)
	}
}

func TestParseImageRef_RetainsDigestForDedup(t *testing.T) {
	// The digest feeds tier 3's dedup cache and is retained even when the tag
	// carries no usable version.
	_, _, d := software.ParseImageRef("app:latest@sha256:deadbeef")
	assert.Equal(t, "sha256:deadbeef", d)
}

// OS base images must emit nothing. CPE files operating systems under part `o`
// and the distiller keeps only part `a`, so an OS name that happens to exist as
// an application product resolves to *different software entirely*: the `a`-part
// `alpine` is alpine_project's Pine-successor email client (versions 2.x), not
// Alpine Linux (o:alpinelinux:alpine_linux). Because that product has exactly
// one vendor, the sole-vendor rule fires for every version, so `alpine:3.19`
// would emit an email client's identity for the most common base image in
// existence and inherit its CVE set.
//
// OS packages are an explicit non-goal of this design — caligula owns them.
func TestParseImageRef_OSBaseImagesEmitNothing(t *testing.T) {
	for _, in := range []string{
		"alpine:3.19", "alpine:3.19.1", "alpine:3",
		"debian:12", "debian:bookworm-slim",
		"ubuntu:22.04", "ubuntu:24.04",
		"public.ecr.aws/docker/library/alpine:3.18",
	} {
		p, v, _ := software.ParseImageRef(in)
		assert.Emptyf(t, p, "input %q must not resolve to an application product", in)
		assert.Empty(t, v, "input %q", in)
	}
}

func TestDetect_ECSAlpineBaseImageEmitsNothing(t *testing.T) {
	props := map[string]any{"ContainerDefinitions": []any{
		map[string]any{"Image": "alpine:3.19"},
	}}
	assert.Empty(t, software.Detect("AWS::ECS::TaskDefinition", props))
}

func TestDetect_ECSTaskDefinitionImages(t *testing.T) {
	props := map[string]any{"ContainerDefinitions": []any{
		map[string]any{"Image": "nginx:1.25.3"},
		map[string]any{"Image": "app:latest"},
		map[string]any{"NotImage": "x"},
	}}
	got := software.Detect("AWS::ECS::TaskDefinition", props)
	assert.Equal(t, []string{"cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*"}, cpeStrings(got))
	assert.Equal(t, "ecs-image-tag", got[0].Source)
	assert.Contains(t, got[0].Evidence, "nginx:1.25.3")
}

func TestDetect_ECSTaskDefinitionMultipleContainers(t *testing.T) {
	props := map[string]any{"ContainerDefinitions": []any{
		map[string]any{"Image": "nginx:1.25.3"},
		map[string]any{"Image": "public.ecr.aws/docker/library/postgres:15.4"},
	}}
	assert.ElementsMatch(t, []string{
		"cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*",
		"cpe:2.3:a:postgresql:postgresql:15.4:*:*:*:*:*:*:*",
	}, cpeStrings(software.Detect("AWS::ECS::TaskDefinition", props)))
}

func TestDetect_ECSMalformedContainerDefinitions(t *testing.T) {
	for _, props := range []map[string]any{
		{"ContainerDefinitions": "not a list"},
		{"ContainerDefinitions": []any{"not a map"}},
		{"ContainerDefinitions": []any{map[string]any{"Image": 42}}},
		{"ContainerDefinitions": []any{nil}},
		{"ContainerDefinitions": nil},
	} {
		assert.NotPanics(t, func() {
			assert.Empty(t, software.Detect("AWS::ECS::TaskDefinition", props))
		})
	}
}

func TestDetect_LambdaImageURI(t *testing.T) {
	props := map[string]any{
		"PackageType": "Image",
		"Code":        map[string]any{"ImageUri": "public.ecr.aws/docker/library/nginx:1.25.3"},
	}
	got := software.Detect("AWS::Lambda::Function", props)
	assert.Equal(t, []string{"cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*"}, cpeStrings(got))
	assert.Equal(t, "lambda-image-uri", got[0].Source)
}

func TestDetect_LambdaImageURIIgnoredForZipPackages(t *testing.T) {
	// Code.ImageUri is only meaningful when PackageType is Image.
	props := map[string]any{
		"PackageType": "Zip",
		"Code":        map[string]any{"ImageUri": "nginx:1.25.3"},
	}
	assert.Empty(t, software.Detect("AWS::Lambda::Function", props))
}

func TestDetect_LambdaCarriesBothRuntimeAndImageDecoders(t *testing.T) {
	// One resource type, two unrelated places software can live, each with its
	// own Source.
	props := map[string]any{
		"Runtime":     "python3.12.1",
		"PackageType": "Image",
		"Code":        map[string]any{"ImageUri": "nginx:1.25.3"},
	}
	got := software.Detect("AWS::Lambda::Function", props)
	sources := map[string]string{}
	for _, tech := range got {
		sources[tech.Source] = tech.CPE
	}
	assert.Equal(t, "cpe:2.3:a:python:python:3.12.1:*:*:*:*:*:*:*", sources["lambda-runtime"])
	assert.Equal(t, "cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*", sources["lambda-image-uri"])
}
