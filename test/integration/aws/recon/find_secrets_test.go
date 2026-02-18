//go:build integration

package recon

import (
	"context"
	"strings"
	"testing"

	_ "github.com/praetorian-inc/aurelian/pkg/modules/aws/recon" // register modules
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// findingsContainResource checks whether any finding references a resource
// whose ResourceRef or FilePath contains the given substring.
func findingsContainResource(findings []output.SecretFinding, resourceSubstr string) bool {
	for _, f := range findings {
		if strings.Contains(f.ResourceRef, resourceSubstr) || strings.Contains(f.FilePath, resourceSubstr) {
			return true
		}
	}
	return false
}

// findingsContainSecret checks whether any finding's Match field contains the
// given secret substring.
func findingsContainSecret(findings []output.SecretFinding, secret string) bool {
	for _, f := range findings {
		if strings.Contains(f.Match, secret) {
			return true
		}
	}
	return false
}

func TestFindSecretsEC2UserData(t *testing.T) {
	// Step 1: Create fixture and provision infrastructure with known fake secrets
	fixture := testutil.NewFixture(t, "aws/recon/find-secrets")
	fixture.Setup()

	region := fixture.Output("region")
	instanceID := fixture.Output("instance_id")
	testSecret := fixture.Output("test_secret")

	// Step 2: Retrieve the find-secrets module from the registry
	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "find-secrets")
	if !ok {
		t.Skip("find-secrets module not registered in plugin system")
	}

	// Step 3: Run find-secrets against EC2 instances only
	results, err := mod.Run(plugin.Config{
		Args: map[string]any{
			"resource-type": []string{"AWS::EC2::Instance"},
			"regions":       []string{region},
		},
		Context: context.Background(),
	})
	require.NoError(t, err)

	// Step 4: Verify results
	testutil.AssertMinResults(t, results, 1)

	findings, ok := results[0].Data.([]output.SecretFinding)
	require.True(t, ok, "results data should be []output.SecretFinding")
	assert.NotEmpty(t, findings, "expected at least one secret finding from EC2 user data")

	assert.True(t, findingsContainResource(findings, instanceID),
		"expected findings to reference instance ID %s", instanceID)
	assert.True(t, findingsContainSecret(findings, testSecret),
		"expected findings to contain test secret %s", testSecret)
}

func TestFindSecretsLambdaCode(t *testing.T) {
	// Step 1: Create fixture and provision infrastructure with known fake secrets
	fixture := testutil.NewFixture(t, "aws/recon/find-secrets")
	fixture.Setup()

	region := fixture.Output("region")
	lambdaFunctionName := fixture.Output("lambda_function_name")
	testSecret := fixture.Output("test_secret")

	// Step 2: Retrieve the find-secrets module from the registry
	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "find-secrets")
	if !ok {
		t.Skip("find-secrets module not registered in plugin system")
	}

	// Step 3: Run find-secrets against Lambda functions only
	results, err := mod.Run(plugin.Config{
		Args: map[string]any{
			"resource-type": []string{"AWS::Lambda::Function"},
			"regions":       []string{region},
		},
		Context: context.Background(),
	})
	require.NoError(t, err)

	// Step 4: Verify results
	testutil.AssertMinResults(t, results, 1)

	findings, ok := results[0].Data.([]output.SecretFinding)
	require.True(t, ok, "results data should be []output.SecretFinding")
	assert.NotEmpty(t, findings, "expected at least one secret finding from Lambda code")

	assert.True(t, findingsContainResource(findings, lambdaFunctionName),
		"expected findings to reference Lambda function %s", lambdaFunctionName)
	assert.True(t, findingsContainSecret(findings, testSecret),
		"expected findings to contain test secret %s", testSecret)
}

func TestFindSecretsCloudFormationTemplate(t *testing.T) {
	// Step 1: Create fixture and provision infrastructure with known fake secrets
	fixture := testutil.NewFixture(t, "aws/recon/find-secrets")
	fixture.Setup()

	region := fixture.Output("region")
	stackName := fixture.Output("cloudformation_stack_name")
	testSecret := fixture.Output("test_secret")

	// Step 2: Retrieve the find-secrets module from the registry
	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "find-secrets")
	if !ok {
		t.Skip("find-secrets module not registered in plugin system")
	}

	// Step 3: Run find-secrets against CloudFormation stacks only
	results, err := mod.Run(plugin.Config{
		Args: map[string]any{
			"resource-type": []string{"AWS::CloudFormation::Stack"},
			"regions":       []string{region},
		},
		Context: context.Background(),
	})
	require.NoError(t, err)

	// Step 4: Verify results
	testutil.AssertMinResults(t, results, 1)

	findings, ok := results[0].Data.([]output.SecretFinding)
	require.True(t, ok, "results data should be []output.SecretFinding")
	assert.NotEmpty(t, findings, "expected at least one secret finding from CloudFormation template")

	assert.True(t, findingsContainResource(findings, stackName),
		"expected findings to reference CloudFormation stack %s", stackName)
	assert.True(t, findingsContainSecret(findings, testSecret),
		"expected findings to contain test secret %s", testSecret)
}

func TestFindSecretsCloudWatchLogs(t *testing.T) {
	// Step 1: Create fixture and provision infrastructure with known fake secrets
	fixture := testutil.NewFixture(t, "aws/recon/find-secrets")
	fixture.Setup()

	region := fixture.Output("region")
	logGroupName := fixture.Output("log_group_name")
	testSecret := fixture.Output("test_secret")

	// Step 2: Retrieve the find-secrets module from the registry
	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "find-secrets")
	if !ok {
		t.Skip("find-secrets module not registered in plugin system")
	}

	// Step 3: Run find-secrets against CloudWatch log groups only
	results, err := mod.Run(plugin.Config{
		Args: map[string]any{
			"resource-type": []string{"AWS::Logs::LogGroup"},
			"regions":       []string{region},
			"max-events":    100,
			"max-streams":   5,
		},
		Context: context.Background(),
	})
	require.NoError(t, err)

	// Step 4: Verify results
	testutil.AssertMinResults(t, results, 1)

	findings, ok := results[0].Data.([]output.SecretFinding)
	require.True(t, ok, "results data should be []output.SecretFinding")
	assert.NotEmpty(t, findings, "expected at least one secret finding from CloudWatch Logs")

	assert.True(t, findingsContainResource(findings, logGroupName),
		"expected findings to reference log group %s", logGroupName)
	assert.True(t, findingsContainSecret(findings, testSecret),
		"expected findings to contain test secret %s", testSecret)
}
