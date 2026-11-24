package enrichers_test

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/praetorian-inc/aurelian/pkg/modules/aws/enrichers"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/software"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockLambdaCodeClient struct {
	out   *lambda.GetFunctionOutput
	err   error
	calls int
}

func (m *mockLambdaCodeClient) GetFunction(_ context.Context, _ *lambda.GetFunctionInput, _ ...func(*lambda.Options)) (*lambda.GetFunctionOutput, error) {
	m.calls++
	return m.out, m.err
}

func imageResource(props map[string]any) *output.AWSResource {
	return &output.AWSResource{
		ResourceType: "AWS::Lambda::Function",
		ResourceID:   "my-function",
		Properties:   props,
	}
}

var enricherCfg = plugin.EnricherConfig{Context: context.Background()}

// The cost control. PackageType arrives free from ListFunctions, and it is the
// only thing standing between this enricher and a GetFunction call per
// function on list-all and public-resources — which is the design's anti-goal.
// A zip function, and a function whose PackageType is unknown, must cost zero
// API calls.
func TestFetchFunctionImage_CallsNothingUnlessPackageTypeIsImage(t *testing.T) {
	for _, tc := range []struct {
		name  string
		props map[string]any
	}{
		{"zip package", map[string]any{"PackageType": "Zip"}},
		{"package type absent", map[string]any{"FunctionName": "my-function"}},
		{"package type is not a string", map[string]any{"PackageType": 7}},
		{"empty properties", map[string]any{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &mockLambdaCodeClient{}
			r := imageResource(tc.props)
			require.NoError(t, enrichers.FetchFunctionImage(enricherCfg, r, client))
			assert.Zero(t, client.calls, "must not call GetFunction")
			assert.NotContains(t, r.Properties, "Code")
		})
	}
}

func TestFetchFunctionImage_FetchesImageURIForImagePackages(t *testing.T) {
	client := &mockLambdaCodeClient{out: &lambda.GetFunctionOutput{
		Code: &lambdatypes.FunctionCodeLocation{
			ImageUri:         aws.String("public.ecr.aws/lambda/python:3.12"),
			ResolvedImageUri: aws.String("public.ecr.aws/lambda/python@sha256:abc123"),
		},
	}}
	r := imageResource(map[string]any{"PackageType": "Image"})

	require.NoError(t, enrichers.FetchFunctionImage(enricherCfg, r, client))
	assert.Equal(t, 1, client.calls)

	code, ok := r.Properties["Code"].(map[string]any)
	require.True(t, ok, "Code must be a nested map, the shape software.Detect reads")
	assert.Equal(t, "public.ecr.aws/lambda/python:3.12", code["ImageUri"])
	assert.Equal(t, "public.ecr.aws/lambda/python@sha256:abc123", code["ResolvedImageUri"])
}

// Code.Location is a presigned S3 URL that grants anyone holding it the
// function's deployment package. It must never reach Properties, which is
// serialised into output and shipped to guard.
func TestFetchFunctionImage_NeverCopiesThePresignedCodeLocation(t *testing.T) {
	client := &mockLambdaCodeClient{out: &lambda.GetFunctionOutput{
		Code: &lambdatypes.FunctionCodeLocation{
			ImageUri: aws.String("public.ecr.aws/lambda/python:3.12"),
			Location: aws.String("https://prod-iad-c1-djt.s3.amazonaws.com/snapshots/x?X-Amz-Signature=deadbeef"),
			SourceKMSKeyArn: aws.String(
				"arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000"),
		},
	}}
	r := imageResource(map[string]any{"PackageType": "Image"})
	require.NoError(t, enrichers.FetchFunctionImage(enricherCfg, r, client))

	code := r.Properties["Code"].(map[string]any)
	assert.NotContains(t, code, "Location")
	assert.NotContains(t, code, "SourceKMSKeyArn")
	assert.Len(t, code, 1)
}

func TestFetchFunctionImage_IsBestEffort(t *testing.T) {
	for _, tc := range []struct {
		name   string
		client *mockLambdaCodeClient
	}{
		{"access denied", &mockLambdaCodeClient{err: errors.New("AccessDeniedException")}},
		{"function vanished mid-scan", &mockLambdaCodeClient{
			err: &lambdatypes.ResourceNotFoundException{}}},
		{"no code in response", &mockLambdaCodeClient{out: &lambda.GetFunctionOutput{}}},
		{"code carries no image uri", &mockLambdaCodeClient{out: &lambda.GetFunctionOutput{
			Code: &lambdatypes.FunctionCodeLocation{Location: aws.String("https://example/x")}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := imageResource(map[string]any{"PackageType": "Image"})
			// An enricher that returned an error here would fail the whole
			// resource over a best-effort lookup.
			assert.NoError(t, enrichers.FetchFunctionImage(enricherCfg, r, tc.client))
			assert.NotContains(t, r.Properties, "Code")
		})
	}
}

// Hydration from another enricher may already have supplied an image URI.
// Re-fetching it would pay for a value already in hand.
func TestFetchFunctionImage_SkipsWhenImageURIAlreadyPresent(t *testing.T) {
	client := &mockLambdaCodeClient{}
	r := imageResource(map[string]any{
		"PackageType": "Image",
		"Code":        map[string]any{"ImageUri": "nginx:1.25.3"},
	})
	require.NoError(t, enrichers.FetchFunctionImage(enricherCfg, r, client))
	assert.Zero(t, client.calls)
	assert.Equal(t, "nginx:1.25.3", r.Properties["Code"].(map[string]any)["ImageUri"])
}

// The end the whole chain exists for: a function enumerated by ListFunctions,
// enriched with its image reference, decodes to a CPE. If the property shape
// this enricher writes ever drifts from the one software.Detect reads, the two
// halves pass their own tests and emit nothing together.
func TestFetchFunctionImage_ProducesAPropertyBagDetectCanDecode(t *testing.T) {
	client := &mockLambdaCodeClient{out: &lambda.GetFunctionOutput{
		Code: &lambdatypes.FunctionCodeLocation{
			ImageUri: aws.String("public.ecr.aws/lambda/python:3.12"),
		},
	}}
	r := imageResource(map[string]any{"PackageType": "Image"})
	require.NoError(t, enrichers.FetchFunctionImage(enricherCfg, r, client))

	got := software.Detect(r.ResourceType, r.Properties)
	require.Len(t, got, 1)
	assert.Equal(t, "cpe:2.3:a:python:python:3.12:*:*:*:*:*:*:*", got[0].CPE)
	assert.Equal(t, "lambda-image-uri", got[0].Source)
}

// A customer's own application image is not CPE-identifiable software, and
// guessing a product for it is the confidently-wrong output the design forbids.
func TestFetchFunctionImage_PrivateECRImageDecodesToNothing(t *testing.T) {
	client := &mockLambdaCodeClient{out: &lambda.GetFunctionOutput{
		Code: &lambdatypes.FunctionCodeLocation{
			ImageUri: aws.String("123456789012.dkr.ecr.us-east-2.amazonaws.com/my-app:1.0.0"),
		},
	}}
	r := imageResource(map[string]any{"PackageType": "Image"})
	require.NoError(t, enrichers.FetchFunctionImage(enricherCfg, r, client))
	assert.Empty(t, software.Detect(r.ResourceType, r.Properties))
}
