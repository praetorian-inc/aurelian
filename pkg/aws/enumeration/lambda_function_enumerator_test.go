package enumeration

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/stretchr/testify/assert"
)

func TestBuildLambdaFunctionResource(t *testing.T) {
	fn := lambdatypes.FunctionConfiguration{
		FunctionName: aws.String("pl-prod-lambda-003-target"),
		FunctionArn:  aws.String("arn:aws:lambda:us-east-1:123456789012:function:pl-prod-lambda-003-target"),
		Role:         aws.String("arn:aws:iam::123456789012:role/pl-prod-lambda-003-exec-role"),
		LastModified: aws.String("2026-08-24T12:34:56.789+0000"),
	}

	r := buildLambdaFunctionResource(fn, "123456789012", "us-east-1")

	assert.Equal(t, "AWS::Lambda::Function", r.ResourceType)
	assert.Equal(t, "pl-prod-lambda-003-target", r.ResourceID)
	assert.Equal(t, "arn:aws:lambda:us-east-1:123456789012:function:pl-prod-lambda-003-target", r.ARN)
	assert.Equal(t, "123456789012", r.AccountRef)
	assert.Equal(t, "us-east-1", r.Region)
	assert.Equal(t, time.Date(2026, time.August, 24, 12, 34, 56, 789000000, time.UTC), *r.LastModified)
	// Role must be captured under "Role" so NodeFromAWSResource promotes it to a top-level
	// node prop and resource_to_role.yaml matches resource.Role = role.Arn for HAS_ROLE.
	assert.Equal(t, "arn:aws:iam::123456789012:role/pl-prod-lambda-003-exec-role", r.Properties["Role"])
	// Functions are collected independently of any resource policy.
	assert.Nil(t, r.ResourcePolicy)
}

func TestBuildLambdaFunctionResourceNoRole(t *testing.T) {
	// A function with no execution role emits an empty Role string (fail-closed):
	// resource_to_role.yaml will not match an empty string to any role ARN, so no
	// HAS_ROLE edge is created.
	fn := lambdatypes.FunctionConfiguration{
		FunctionName: aws.String("pl-norole"),
		FunctionArn:  aws.String("arn:aws:lambda:us-west-2:123456789012:function:pl-norole"),
	}

	r := buildLambdaFunctionResource(fn, "123456789012", "us-west-2")

	assert.Equal(t, "pl-norole", r.ResourceID)
	assert.Equal(t, "", r.Properties["Role"])
}

// Runtime and PackageType are the tier-1 inputs pkg/software decodes, and
// ListFunctions returns both inside the FunctionConfiguration this builder
// already receives. They were dropped on the floor, which made Runtime look
// like a sparse-CloudControl problem and bought a GetResource per function to
// fetch back a value that was already in memory.
func TestBuildLambdaFunctionResourceSurfacesRuntimeAndPackageType(t *testing.T) {
	fn := lambdatypes.FunctionConfiguration{
		FunctionName: aws.String("pl-zip"),
		FunctionArn:  aws.String("arn:aws:lambda:us-east-1:123456789012:function:pl-zip"),
		Runtime:      lambdatypes.RuntimePython312,
		PackageType:  lambdatypes.PackageTypeZip,
	}

	r := buildLambdaFunctionResource(fn, "123456789012", "us-east-1")

	assert.Equal(t, "python3.12", r.Properties["Runtime"])
	assert.Equal(t, "Zip", r.Properties["PackageType"])
}

// An image-packaged function reports no managed runtime. Writing an empty
// Runtime would make the tier-1 decoder see a present-but-useless key, so the
// absent value stays absent.
func TestBuildLambdaFunctionResourceOmitsEmptyRuntime(t *testing.T) {
	fn := lambdatypes.FunctionConfiguration{
		FunctionName: aws.String("pl-image"),
		FunctionArn:  aws.String("arn:aws:lambda:us-east-1:123456789012:function:pl-image"),
		PackageType:  lambdatypes.PackageTypeImage,
	}

	r := buildLambdaFunctionResource(fn, "123456789012", "us-east-1")

	assert.NotContains(t, r.Properties, "Runtime")
	assert.Equal(t, "Image", r.Properties["PackageType"])
}
