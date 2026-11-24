//go:build integration

package recon

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/praetorian-inc/aurelian/pkg/model"
	_ "github.com/praetorian-inc/aurelian/pkg/modules/aws/enrichers" // register enrichers
	_ "github.com/praetorian-inc/aurelian/pkg/modules/aws/recon"     // register modules
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const imageConfigRegion = "us-east-2"

// TestImageConfigTechnologyEmission deploys real AWS resources and proves the
// phase-3 claim end to end: that the software an image runs is identifiable
// from its config blob, including for images whose tag says nothing.
//
// It self-provisions over the SDK rather than Terraform, following the same
// decision the ecr-dump integration tests made: an ECR repository, an image
// pushed to it in-process, and a task definition referencing it are three API
// calls and need no Docker daemon.
//
// Nothing here is mocked. The ECR repository, the pushed image, the task
// definition, the ECR authorization token and the Docker Hub pulls are all
// real.
func TestImageConfigTechnologyEmission(t *testing.T) {
	ctx := context.Background()

	awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(imageConfigRegion))
	require.NoError(t, err, "AWS credentials are required for this test")

	ecrClient := ecr.NewFromConfig(awsCfg)
	ecsClient := ecs.NewFromConfig(awsCfg)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	repoName := "aurelian-imgcfg-" + suffix

	t.Cleanup(createECRRepo(t, ecrClient, repoName))

	// The image's TAG is deliberately meaningless. Everything this test
	// asserts about it has to come from the config blob.
	//
	// Its environment is what a private application image inherits from an
	// official base: a marker naming the runtime, beside junk that must not be
	// emitted. GOSU_VERSION and YARN_VERSION are real values observed in real
	// official images (see pkg/software/testdata/imageconfig/FINDINGS.md).
	privateRef := pushImageWithConfig(t, ecrClient, repoName, "v1",
		[]string{
			"PATH=/usr/local/bin:/usr/bin",
			"PYTHON_VERSION=3.11.18",
			"GOSU_VERSION=1.19",
			"YARN_VERSION=1.22.22",
		},
		[]string{"python3", "app.py"},
	)
	t.Logf("pushed %s", privateRef)

	family := "aurelian-imgcfg-" + suffix
	t.Cleanup(registerTaskDefinition(t, ecsClient, family, []string{
		privateRef,
		// A derived public image. wordpress is not in the tier-2 base-name
		// table and its tag cannot be parsed into a product, but its config
		// carries PHP_VERSION inherited from the php base.
		"wordpress:6-php8.2-apache",
		// Two markers on one image: Tomcat is what the entrypoint runs, the
		// JDK is what it runs on. Both are the stack.
		"tomcat:10.1.62",
	}))

	t.Run("flag off emits only what the tag can identify", func(t *testing.T) {
		res := findResource(t, listAllWithImageConfigs(t, ecsType, false), family)
		require.NotNil(t, res, "task definition %q not found", family)

		got := cpesOf(*res)
		assert.Equal(t, []string{"cpe:2.3:a:apache:tomcat:10.1.62:*:*:*:*:*:*:*"}, got,
			"only tomcat:10.1.62 has a parseable base name and tag; the ECR image and wordpress must emit nothing")
	})

	t.Run("flag on identifies images no tag could", func(t *testing.T) {
		res := findResource(t, listAllWithImageConfigs(t, ecsType, true), family)
		require.NotNil(t, res, "task definition %q not found", family)

		got := cpesOf(*res)

		// The phase's reason to exist, in two assertions.
		assert.Contains(t, got, "cpe:2.3:a:python:python:3.11:*:*:*:*:*:*:*",
			"the ECR image's runtime is only visible in its config blob, and reading it proves the ECR auth path")
		assert.Contains(t, got, "cpe:2.3:a:php:php:8.2.31:*:*:*:*:*:*:*",
			"wordpress inherits PHP_VERSION from its base; ParseImageRef cannot reach it")

		// The runtime beneath an entrypoint, which no tag carries.
		assert.Contains(t, got, "cpe:2.3:a:oracle:openjdk:25.0.5.1:*:*:*:*:*:*:*",
			"tomcat:10.1.62 carries JAVA_VERSION as well as TOMCAT_VERSION")

		// What the tag already found must survive, exactly once.
		assert.Contains(t, got, "cpe:2.3:a:apache:tomcat:10.1.62:*:*:*:*:*:*:*")
		assert.Len(t, uniq(got), len(got), "a CPE found by both the tag and the config must be emitted once")

		// The allowlist holds against real values on a real image.
		for _, c := range got {
			for _, forbidden := range []string{"gosu", "yarn", ":a:alpine", ":a:voxpupuli"} {
				assert.NotContains(t, c, forbidden, "emitted %q", c)
			}
		}
	})

	t.Run("provenance distinguishes observed from truncated", func(t *testing.T) {
		res := findResource(t, listAllWithImageConfigs(t, ecsType, true), family)
		require.NotNil(t, res)

		sources := map[string]string{}
		evidence := map[string]string{}
		for _, tech := range res.Technologies {
			sources[tech.CPE] = tech.Source
			evidence[tech.CPE] = tech.Evidence
		}

		// PYTHON_VERSION=3.11.18 has no dictionary row; 3.11 does. A consumer
		// must be able to tell that the emitted version is coarser than the
		// observed one, because the emitted criteria matches 3.11.x CVEs that
		// 3.11.18 is already patched for.
		assert.Equal(t, "image-config-env-truncated", sources["cpe:2.3:a:python:python:3.11:*:*:*:*:*:*:*"])
		assert.Contains(t, evidence["cpe:2.3:a:python:python:3.11:*:*:*:*:*:*:*"], "PYTHON_VERSION=3.11.18",
			"evidence must carry what was observed, not what was emitted")

		// PHP_VERSION=8.2.31 resolves exactly.
		assert.Equal(t, "image-config-env", sources["cpe:2.3:a:php:php:8.2.31:*:*:*:*:*:*:*"])

		// Tomcat was found by the tag first and keeps that provenance.
		assert.Equal(t, "ecs-image-tag", sources["cpe:2.3:a:apache:tomcat:10.1.62:*:*:*:*:*:*:*"])
	})

	t.Run("every emitted CPE satisfies guard's Technology key regex", func(t *testing.T) {
		res := findResource(t, listAllWithImageConfigs(t, ecsType, true), family)
		require.NotNil(t, res)
		require.NotEmpty(t, res.Technologies)

		for _, tech := range res.Technologies {
			assert.Regexp(t, `^cpe:2\.3(:[^:]+){11}$`, tech.CPE)
			assert.NotEmpty(t, tech.Source)
			assert.NotEmpty(t, tech.Evidence)
		}
	})
}

// TestImageConfigUnreachableImageDoesNotFailTheScan proves the fail-soft rule
// against a real registry: a reference that cannot be pulled contributes no
// technology and does not stop the module or the resource.
func TestImageConfigUnreachableImageDoesNotFailTheScan(t *testing.T) {
	ctx := context.Background()
	awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(imageConfigRegion))
	require.NoError(t, err)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	family := "aurelian-imgcfg-missing-" + suffix

	t.Cleanup(registerTaskDefinition(t, ecs.NewFromConfig(awsCfg), family, []string{
		// A repository that does not exist in this account.
		fmt.Sprintf("000000000000.dkr.ecr.%s.amazonaws.com/no-such-repo:v1", imageConfigRegion),
		// A tag that does not exist in a repository that does.
		"library/nginx:0.0.0-does-not-exist",
		// One image that does work, so a passing test is not vacuous.
		"tomcat:10.1.62",
	}))

	res := findResource(t, listAllWithImageConfigs(t, ecsType, true), family)
	require.NotNil(t, res, "a resource with unreachable images must still be emitted")
	assert.Contains(t, cpesOf(*res), "cpe:2.3:a:apache:tomcat:10.1.62:*:*:*:*:*:*:*",
		"the reachable image's technology must survive its neighbours failing")
}

// --- provisioning helpers ---------------------------------------------------

func createECRRepo(t *testing.T, client *ecr.Client, repoName string) func() {
	t.Helper()
	_, err := client.CreateRepository(context.TODO(), &ecr.CreateRepositoryInput{
		RepositoryName:     &repoName,
		ImageTagMutability: ecrtypes.ImageTagMutabilityMutable,
	})
	require.NoError(t, err, "failed to create ECR repo %s", repoName)

	return func() {
		force := true
		if _, err := client.DeleteRepository(context.TODO(), &ecr.DeleteRepositoryInput{
			RepositoryName: &repoName,
			Force:          force,
		}); err != nil {
			t.Logf("warning: failed to delete ECR repo %s: %v", repoName, err)
		}
	}
}

// pushImageWithConfig builds a one-layer image in process, sets its config
// environment and command, pushes it, and returns the reference.
//
// Setting Config.Env is the whole point: this is what an image inherits from
// an official base, and what this phase reads.
func pushImageWithConfig(t *testing.T, client *ecr.Client, repoName, tag string, env, cmd []string) string {
	t.Helper()
	ctx := context.TODO()

	authResp, err := client.GetAuthorizationToken(ctx, &ecr.GetAuthorizationTokenInput{})
	require.NoError(t, err)
	require.NotEmpty(t, authResp.AuthorizationData)

	decoded, err := base64.StdEncoding.DecodeString(*authResp.AuthorizationData[0].AuthorizationToken)
	require.NoError(t, err)
	user, pass, found := strings.Cut(string(decoded), ":")
	require.True(t, found, "unexpected ECR auth token format")

	accountID := strings.TrimPrefix(*authResp.AuthorizationData[0].ProxyEndpoint, "https://")
	accountID, _, _ = strings.Cut(accountID, ".")

	layer, err := tarGzLayer("app/app.py", []byte("print('hello')\n"))
	require.NoError(t, err)

	img, err := mutate.AppendLayers(empty.Image, layer)
	require.NoError(t, err)

	cf, err := img.ConfigFile()
	require.NoError(t, err)
	cf = cf.DeepCopy()
	cf.Config.Env = env
	cf.Config.Cmd = cmd
	img, err = mutate.ConfigFile(img, cf)
	require.NoError(t, err)

	imageURI := fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com/%s:%s", accountID, imageConfigRegion, repoName, tag)
	ref, err := name.ParseReference(imageURI)
	require.NoError(t, err)

	require.NoError(t, remote.Write(ref, img, remote.WithAuth(authn.FromConfig(authn.AuthConfig{
		Username: user,
		Password: pass,
	}))))

	// ECR is read-after-write for the manifest but the tag index settles a
	// moment later.
	time.Sleep(2 * time.Second)
	return imageURI
}

func tarGzLayer(path string, content []byte) (v1.Layer, error) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	if err := tw.WriteHeader(&tar.Header{
		Name: path, Size: int64(len(content)), Mode: 0o644, Typeflag: tar.TypeReg,
	}); err != nil {
		return nil, err
	}
	if _, err := tw.Write(content); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gw.Close(); err != nil {
		return nil, err
	}
	return tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(buf.Bytes())), nil
	}, tarball.WithCompressedCaching)
}

// registerTaskDefinition registers a task definition naming the given images.
// Registration is free and instantaneous: nothing is scheduled, no cluster
// exists, and no capacity is reserved.
func registerTaskDefinition(t *testing.T, client *ecs.Client, family string, images []string) func() {
	t.Helper()

	containers := make([]ecstypes.ContainerDefinition, 0, len(images))
	for i, img := range images {
		containers = append(containers, ecstypes.ContainerDefinition{
			Name:      awsString(fmt.Sprintf("c%d", i)),
			Image:     awsString(img),
			Cpu:       0,
			Memory:    awsInt32(128),
			Essential: awsBool(i == 0),
		})
	}

	out, err := client.RegisterTaskDefinition(context.TODO(), &ecs.RegisterTaskDefinitionInput{
		Family:               &family,
		NetworkMode:          ecstypes.NetworkModeBridge,
		ContainerDefinitions: containers,
	})
	require.NoError(t, err, "failed to register task definition %s", family)

	arn := *out.TaskDefinition.TaskDefinitionArn
	return func() {
		if _, err := client.DeregisterTaskDefinition(context.TODO(), &ecs.DeregisterTaskDefinitionInput{
			TaskDefinition: &arn,
		}); err != nil {
			t.Logf("warning: failed to deregister task definition %s: %v", arn, err)
		}
	}
}

// listAllWithImageConfigs runs list-all for one resource type with the
// image-config read on or off.
func listAllWithImageConfigs(t *testing.T, resourceType string, scanImageConfigs bool) []model.AurelianModel {
	t.Helper()

	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "list-all")
	require.True(t, ok, "list-all module not registered")

	results, err := testutil.RunAndCollect(t, mod, plugin.Config{
		Args: map[string]any{
			"resource-type": []string{resourceType},
			"regions":       []string{imageConfigRegion},
			"scan-type":     "full",
			"image-configs": scanImageConfigs,
		},
		Context: context.Background(),
	})
	require.NoError(t, err, "list-all failed for %s", resourceType)
	return results
}

func uniq(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func awsString(s string) *string { return &s }
func awsInt32(i int32) *int32    { return &i }
func awsBool(b bool) *bool       { return &b }
