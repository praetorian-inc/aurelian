//go:build integration

package recon

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
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

const (
	imageConfigRegion  = "us-east-2"
	imageConfigProfile = "default"
)

// Public images are pinned BY DIGEST so the expected CPE sets below can be
// exact and stay exact. Docker Hub rebuilds `tomcat:10.1.62` and
// `wordpress:6-php8.2-apache` in place, and when it does their JAVA_VERSION
// and PHP_VERSION move; a test asserting those by tag would fail with no code
// change.
//
// The `name:tag@digest` form pins the content while leaving the tag readable,
// which matters because both paths are under test: the tag feeds tier 2 and
// the config feeds tier 3.
//
// Resolved 2026-11-24. Markers carried at these digests:
//
//	tomcat    -> JAVA_VERSION=jdk-25.0.5.1+2, TOMCAT_VERSION=10.1.62
//	wordpress -> PHP_VERSION=8.2.31 (inherited from the php base)
const (
	tomcatRef    = "tomcat:10.1.62@sha256:ea2ac195187bc1bb91c9a7fc06bfed33b9aee7c6a7e549045c1c75beee87e483"
	wordpressRef = "wordpress:6-php8.2-apache@sha256:29a3af5db27d8c1716367575280bbf449cd231ced707daf8ce411895c042ed76"
)

// Expected CPEs, written out rather than computed. A test that derived these
// by calling software.Detect would compare the system to itself and pass no
// matter what it emitted.
//
// A product resolves under EVERY vendor NVD publishes it under, and the
// observed version is emitted verbatim — see pkg/cpe.ResolveVendors for the
// NVD CVE measurement behind that. So the expected set for one piece of
// software is one CPE per vendor, all at the observed version.
//
// "Every vendor" means the union of two corpora since 2026-11-24: the CPE
// dictionary (names that exist) and the CVE feeds' applicability criteria
// (names that are used). sun:openjdk and php_group:php below come only from
// the second — they have no dictionary record at all, and between them are
// cited by 20 live CVEs that were unreachable before.
var (
	cpeTomcat = []string{
		"cpe:2.3:a:apache:tomcat:10.1.62:*:*:*:*:*:*:*",
		"cpe:2.3:a:apache_software_foundation:tomcat:10.1.62:*:*:*:*:*:*:*",
	}
	cpeOpenJDK = []string{
		"cpe:2.3:a:oracle:openjdk:25.0.5.1:*:*:*:*:*:*:*",
		"cpe:2.3:a:sun:openjdk:25.0.5.1:*:*:*:*:*:*:*",
	}
	cpePHP = []string{
		"cpe:2.3:a:php:php:8.2.31:*:*:*:*:*:*:*",
		"cpe:2.3:a:php_group:php:8.2.31:*:*:*:*:*:*:*",
	}
	cpePython = []string{
		"cpe:2.3:a:microsoft:python:3.11.18:*:*:*:*:*:*:*",
		"cpe:2.3:a:python:python:3.11.18:*:*:*:*:*:*:*",
		"cpe:2.3:a:python_software_foundation:python:3.11.18:*:*:*:*:*:*:*",
	}
	cpePython312 = []string{
		"cpe:2.3:a:microsoft:python:3.12:*:*:*:*:*:*:*",
		"cpe:2.3:a:python:python:3.12:*:*:*:*:*:*:*",
		"cpe:2.3:a:python_software_foundation:python:3.12:*:*:*:*:*:*:*",
	}
	cpeNode = []string{
		"cpe:2.3:a:joyent:node.js:20.20.2:*:*:*:*:*:*:*",
		"cpe:2.3:a:mongodb:node.js:20.20.2:*:*:*:*:*:*:*",
		"cpe:2.3:a:nodejs:node.js:20.20.2:*:*:*:*:*:*:*",
	}
)

func union(sets ...[]string) []string {
	var out []string
	for _, s := range sets {
		out = append(out, s...)
	}
	return out
}

// TestImageConfigTechnologyEmission proves the phase-3 capability end to end
// against live AWS and live Docker Hub, for all three resource shapes that can
// carry software: an ECS task definition, an image-packaged Lambda function,
// and a zip-packaged Lambda function.
//
// Every assertion is an exact set. "Contains" would let a regression that
// dropped one technology, or invented an extra one, pass unnoticed.
//
// Nothing is mocked. The ECR repository, the pushed images, the task
// definition, the IAM role, both Lambda functions, the ECR authorization token
// and the Docker Hub pulls are all real.
func TestImageConfigTechnologyEmission(t *testing.T) {
	awsCfg := loadAWSConfig(t)

	ecrClient := ecr.NewFromConfig(awsCfg)
	ecsClient := ecs.NewFromConfig(awsCfg)
	lambdaClient := lambda.NewFromConfig(awsCfg)
	iamClient := iam.NewFromConfig(awsCfg)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano()%1_000_000_000)
	repoName := "aurelian-imgcfg-" + suffix
	t.Cleanup(createECRRepo(t, ecrClient, repoName))

	registry := ecrRegistryHost(t, ecrClient)

	// Both images have a deliberately meaningless tag. Everything asserted
	// about them has to come from the config blob.
	//
	// Their environments are what a private application image inherits from an
	// official base: a marker naming the runtime, beside junk that must not be
	// emitted. GOSU_VERSION and YARN_VERSION are observed in real official
	// images.
	appRef := pushImageWithConfig(t, ecrClient, registry, repoName, "app-v1",
		[]string{"PATH=/usr/local/bin", "PYTHON_VERSION=3.11.18", "GOSU_VERSION=1.19", "YARN_VERSION=1.22.22"},
		[]string{"python3", "app.py"})

	fnRef := pushImageWithConfig(t, ecrClient, registry, repoName, "fn-v1",
		[]string{"PATH=/usr/local/bin", "NODE_VERSION=20.20.2", "YARN_VERSION=1.22.22"},
		[]string{"/var/task/index.handler"})

	taskFamily := "aurelian-imgcfg-" + suffix
	t.Cleanup(registerTaskDefinition(t, ecsClient, taskFamily, []string{appRef, wordpressRef, tomcatRef}))

	roleARN := createLambdaRole(t, iamClient, "aurelian-imgcfg-role-"+suffix)

	imageFnName := "aurelian-imgcfg-image-" + suffix
	t.Cleanup(createImageLambda(t, lambdaClient, imageFnName, roleARN, fnRef))

	zipFnName := "aurelian-imgcfg-zip-" + suffix
	t.Cleanup(createZipLambda(t, lambdaClient, zipFnName, roleARN, "python3.12"))

	// One scan per resource type, shared across the cases below.
	ecsOn := listAllForImageConfig(t, ecsType)
	lambdaOn := listAllForImageConfig(t, lambdaType)

	for _, tc := range []struct {
		name    string
		results []model.AurelianModel
		id      string
		expect  []string
		why     string
	}{
		{
			name:    "ECS — the config identifies what the tag cannot",
			results: ecsOn, id: taskFamily,
			expect: union(cpeTomcat, cpeOpenJDK, cpePHP, cpePython),
			why:    "openjdk is the runtime beneath tomcat's entrypoint, php is inherited by wordpress from its base, python comes from a private ECR image whose tag says nothing; tomcat is found by both the tag and the config and must appear once",
		},
		{
			name:    "Lambda/image-packaged — identified from the image config",
			results: lambdaOn, id: imageFnName,
			expect: cpeNode,
			why:    "an image-packaged function has no Runtime and its ECR repository name is not a known product, so this proves the FetchFunctionImage enricher ran before the technology enricher and the config was read from ECR",
		},
		{
			name:    "Lambda/zip-packaged — runtime, no registry call involved",
			results: lambdaOn, id: zipFnName,
			expect: cpePython312,
			why:    "tier 1 reads Runtime=python3.12 directly; the image-config path must not disturb it",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := findResource(t, tc.results, tc.id)
			require.NotNil(t, res, "resource %q not found among %d results", tc.id, len(tc.results))
			assert.ElementsMatch(t, tc.expect, cpesOf(*res),
				"%s emitted the wrong CPE set — %s", tc.id, tc.why)
		})
	}

	t.Run("provenance and verbatim versions", func(t *testing.T) {
		res := findResource(t, ecsOn, taskFamily)
		require.NotNil(t, res)

		source := map[string]string{}
		evidence := map[string]string{}
		for _, tech := range res.Technologies {
			source[tech.CPE] = tech.Source
			evidence[tech.CPE] = tech.Evidence
		}

		// The observed marker value is emitted unchanged. An earlier revision
		// truncated PYTHON_VERSION=3.11.18 to 3.11 to find a dictionary entry
		// and marked it "-truncated"; measured against the live NVD CVE
		// corpus, 3.11.18 matches 15 CVEs through version ranges while the
		// 3.11 substituted for it matched 10 of those plus 1 that does not
		// apply. There is no truncated provenance any more.
		assert.Equal(t, "image-config-env", source[cpePython[1]])
		assert.Contains(t, evidence[cpePython[1]], "PYTHON_VERSION=3.11.18")

		assert.Equal(t, "image-config-env", source[cpePHP[0]])
		assert.Equal(t, "image-config-env", source[cpeOpenJDK[0]])
		assert.Equal(t, "ecs-image-tag", source[cpeTomcat[0]],
			"the tag observed tomcat first and keeps that provenance")

		for _, tech := range res.Technologies {
			assert.NotContains(t, tech.Source, "truncated")
		}
	})

	t.Run("no marker junk reaches the output", func(t *testing.T) {
		// GOSU_VERSION and YARN_VERSION are on the images this test pushed.
		// The exact-set assertions above already prove they are absent; this
		// says so by name, so a failure reads as what it is.
		for _, results := range [][]model.AurelianModel{ecsOn, lambdaOn} {
			for _, id := range []string{taskFamily, imageFnName} {
				res := findResource(t, results, id)
				if res == nil {
					continue
				}
				for _, c := range cpesOf(*res) {
					for _, bad := range []string{"gosu", "yarn", ":a:alpine", ":a:voxpupuli"} {
						assert.NotContains(t, c, bad, "resource %s emitted %q", id, c)
					}
				}
			}
		}
	})

	t.Run("every emitted CPE satisfies guard's Technology key regex", func(t *testing.T) {
		checked := 0
		for _, results := range [][]model.AurelianModel{ecsOn, lambdaOn} {
			for _, id := range []string{taskFamily, imageFnName, zipFnName} {
				res := findResource(t, results, id)
				if res == nil {
					continue
				}
				for _, tech := range res.Technologies {
					checked++
					assert.Regexp(t, `^cpe:2\.3(:[^:]+){11}$`, tech.CPE)
					assert.NotEmpty(t, tech.Source, "technology on %s has no Source", id)
					assert.NotEmpty(t, tech.Evidence, "technology on %s has no Evidence", id)
				}
			}
		}
		require.NotZero(t, checked, "no CPEs were emitted at all; the check is vacuous")
	})
}

// TestImageConfigUnreachableImageDoesNotFailTheScan proves fail-soft against
// real registries: references that cannot be pulled contribute nothing, while
// a reachable image on the same resource still emits.
func TestImageConfigUnreachableImageDoesNotFailTheScan(t *testing.T) {
	awsCfg := loadAWSConfig(t)
	suffix := fmt.Sprintf("%d", time.Now().UnixNano()%1_000_000_000)
	family := "aurelian-imgcfg-missing-" + suffix

	// Both unreachable references must also be unidentifiable from their tag,
	// or this test measures the wrong thing. An earlier revision used
	// "library/nginx:0.0.0-does-not-exist" and found that it emits nginx CPEs
	// at 0.0.0 from the tag alone — correctly, since tier 2 reads the tag and
	// never needs the registry. That is a real property worth knowing, but it
	// is tier 2's and not fail-soft, so it does not belong here.
	t.Cleanup(registerTaskDefinition(t, ecs.NewFromConfig(awsCfg), family, []string{
		fmt.Sprintf("000000000000.dkr.ecr.%s.amazonaws.com/no-such-repo:v1", imageConfigRegion),
		"aurelian-no-such-org/no-such-app:v1",
		tomcatRef,
	}))

	res := findResource(t, listAllForImageConfig(t, ecsType), family)
	require.NotNil(t, res, "a resource with unreachable images must still be emitted")

	// The exact set. openjdk is the load-bearing member: it is reachable ONLY
	// through the config path, so its presence proves the two failures above
	// did not abort the read for the image that worked.
	assert.ElementsMatch(t, union(cpeTomcat, cpeOpenJDK), cpesOf(*res))
}

// --- provisioning -----------------------------------------------------------

func loadAWSConfig(t *testing.T) aws.Config {
	t.Helper()
	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(imageConfigRegion),
		config.WithSharedConfigProfile(imageConfigProfile),
	)
	require.NoError(t, err, "AWS profile %q is required for this test", imageConfigProfile)
	return cfg
}

func ecrRegistryHost(t *testing.T, client *ecr.Client) string {
	t.Helper()
	out, err := client.GetAuthorizationToken(context.TODO(), &ecr.GetAuthorizationTokenInput{})
	require.NoError(t, err)
	require.NotEmpty(t, out.AuthorizationData)
	return strings.TrimPrefix(aws.ToString(out.AuthorizationData[0].ProxyEndpoint), "https://")
}

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
			RepositoryName: &repoName, Force: force,
		}); err != nil {
			t.Logf("warning: failed to delete ECR repo %s: %v", repoName, err)
		}
	}
}

// pushImageWithConfig builds a one-layer image in process, sets its config
// environment and command, pushes it to ECR and returns the reference.
//
// Setting Config.Env is the point: it is what an image inherits from an
// official base and what this phase reads. Architecture and OS are set because
// Lambda refuses an image whose manifest does not declare linux/amd64.
func pushImageWithConfig(t *testing.T, client *ecr.Client, registry, repoName, tag string, env, cmd []string) string {
	t.Helper()

	out, err := client.GetAuthorizationToken(context.TODO(), &ecr.GetAuthorizationTokenInput{})
	require.NoError(t, err)
	decoded, err := base64.StdEncoding.DecodeString(aws.ToString(out.AuthorizationData[0].AuthorizationToken))
	require.NoError(t, err)
	user, pass, found := strings.Cut(string(decoded), ":")
	require.True(t, found, "unexpected ECR auth token format")

	layer, err := tarGzLayer("var/task/index.py", []byte("def handler(event, context):\n    return {}\n"))
	require.NoError(t, err)

	img, err := mutate.AppendLayers(empty.Image, layer)
	require.NoError(t, err)

	cf, err := img.ConfigFile()
	require.NoError(t, err)
	cf = cf.DeepCopy()
	cf.Architecture = "amd64"
	cf.OS = "linux"
	cf.Config.Env = env
	cf.Config.Cmd = cmd
	img, err = mutate.ConfigFile(img, cf)
	require.NoError(t, err)

	ref := fmt.Sprintf("%s/%s:%s", registry, repoName, tag)
	parsed, err := name.ParseReference(ref)
	require.NoError(t, err)
	require.NoError(t, remote.Write(parsed, img, remote.WithAuth(
		authn.FromConfig(authn.AuthConfig{Username: user, Password: pass}))))

	return ref
}

func tarGzLayer(path string, content []byte) (v1.Layer, error) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	// Lambda validates the image at CreateFunction and rejects a layer whose
	// file has no parent directory entries:
	//   CustomerError: MissingParentDirectory: Parent directory does not exist
	// A real docker build always emits them; a hand-built layer must too.
	segments := strings.Split(path, "/")
	for i := 1; i < len(segments); i++ {
		if err := tw.WriteHeader(&tar.Header{
			Name:     strings.Join(segments[:i], "/") + "/",
			Mode:     0o755,
			Typeflag: tar.TypeDir,
		}); err != nil {
			return nil, err
		}
	}

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
// exists, no capacity is reserved.
func registerTaskDefinition(t *testing.T, client *ecs.Client, family string, images []string) func() {
	t.Helper()

	containers := make([]ecstypes.ContainerDefinition, 0, len(images))
	for i, img := range images {
		containers = append(containers, ecstypes.ContainerDefinition{
			Name:      aws.String(fmt.Sprintf("c%d", i)),
			Image:     aws.String(img),
			Memory:    aws.Int32(128),
			Essential: aws.Bool(i == 0),
		})
	}

	out, err := client.RegisterTaskDefinition(context.TODO(), &ecs.RegisterTaskDefinitionInput{
		Family:               &family,
		NetworkMode:          ecstypes.NetworkModeBridge,
		ContainerDefinitions: containers,
	})
	require.NoError(t, err, "failed to register task definition %s", family)

	arn := aws.ToString(out.TaskDefinition.TaskDefinitionArn)
	return func() {
		if _, err := client.DeregisterTaskDefinition(context.TODO(), &ecs.DeregisterTaskDefinitionInput{
			TaskDefinition: &arn,
		}); err != nil {
			t.Logf("warning: failed to deregister task definition %s: %v", arn, err)
		}
	}
}

func createLambdaRole(t *testing.T, client *iam.Client, roleName string) string {
	t.Helper()
	const trust = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`

	out, err := client.CreateRole(context.TODO(), &iam.CreateRoleInput{
		RoleName:                 &roleName,
		AssumeRolePolicyDocument: aws.String(trust),
		Description:              aws.String("aurelian image-config integration test"),
	})
	require.NoError(t, err, "failed to create IAM role %s", roleName)

	t.Cleanup(func() {
		if _, err := client.DeleteRole(context.TODO(), &iam.DeleteRoleInput{RoleName: &roleName}); err != nil {
			t.Logf("warning: failed to delete IAM role %s: %v", roleName, err)
		}
	})

	// IAM is eventually consistent; Lambda rejects a role it cannot yet see.
	time.Sleep(12 * time.Second)
	return aws.ToString(out.Role.Arn)
}

func createImageLambda(t *testing.T, client *lambda.Client, fnName, roleARN, imageURI string) func() {
	t.Helper()
	_, err := client.CreateFunction(context.TODO(), &lambda.CreateFunctionInput{
		FunctionName:  &fnName,
		Role:          &roleARN,
		PackageType:   lambdatypes.PackageTypeImage,
		Code:          &lambdatypes.FunctionCode{ImageUri: &imageURI},
		Architectures: []lambdatypes.Architecture{lambdatypes.ArchitectureX8664},
	})
	require.NoError(t, err, "failed to create image-packaged function %s from %s", fnName, imageURI)

	// Registered BEFORE the wait, not after. CreateFunction can succeed and
	// the function still settle into Failed, and an earlier revision returned
	// the cleanup only on the happy path — so a function that failed to
	// initialise was left behind in the account. An orphan outlives the run
	// and breaks later ones.
	cleanup := deleteLambda(t, client, fnName)
	t.Cleanup(cleanup)

	waitForLambda(t, client, fnName)
	return func() {}
}

func createZipLambda(t *testing.T, client *lambda.Client, fnName, roleARN, runtime string) func() {
	t.Helper()

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	f, err := zw.Create("index.py")
	require.NoError(t, err)
	_, err = f.Write([]byte("def handler(event, context):\n    return {}\n"))
	require.NoError(t, err)
	require.NoError(t, zw.Close())

	_, err = client.CreateFunction(context.TODO(), &lambda.CreateFunctionInput{
		FunctionName: &fnName,
		Role:         &roleARN,
		PackageType:  lambdatypes.PackageTypeZip,
		Runtime:      lambdatypes.Runtime(runtime),
		Handler:      aws.String("index.handler"),
		Code:         &lambdatypes.FunctionCode{ZipFile: buf.Bytes()},
	})
	require.NoError(t, err, "failed to create zip-packaged function %s", fnName)

	// Registered before the wait, for the reason given in createImageLambda.
	t.Cleanup(deleteLambda(t, client, fnName))

	waitForLambda(t, client, fnName)
	return func() {}
}

func waitForLambda(t *testing.T, client *lambda.Client, fnName string) {
	t.Helper()
	for range 30 {
		out, err := client.GetFunction(context.TODO(), &lambda.GetFunctionInput{FunctionName: &fnName})
		if err == nil && out.Configuration != nil && out.Configuration.State == lambdatypes.StateActive {
			return
		}
		if err == nil && out.Configuration != nil && out.Configuration.State == lambdatypes.StateFailed {
			t.Fatalf("function %s failed to create: %s", fnName, aws.ToString(out.Configuration.StateReason))
		}
		time.Sleep(4 * time.Second)
	}
	t.Fatalf("function %s did not become Active", fnName)
}

func deleteLambda(t *testing.T, client *lambda.Client, fnName string) func() {
	return func() {
		if _, err := client.DeleteFunction(context.TODO(), &lambda.DeleteFunctionInput{FunctionName: &fnName}); err != nil {
			t.Logf("warning: failed to delete function %s: %v", fnName, err)
		}
	}
}

// listAllForImageConfig runs list-all for one resource type against the
// configured profile.
func listAllForImageConfig(t *testing.T, resourceType string) []model.AurelianModel {
	t.Helper()

	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "list-all")
	require.True(t, ok, "list-all module not registered")

	results, err := testutil.RunAndCollect(t, mod, plugin.Config{
		Args: map[string]any{
			"profile":       imageConfigProfile,
			"resource-type": []string{resourceType},
			"regions":       []string{imageConfigRegion},
			"scan-type":     "full",
		},
		Context: context.Background(),
	})
	require.NoError(t, err, "list-all failed for %s", resourceType)
	return results
}
