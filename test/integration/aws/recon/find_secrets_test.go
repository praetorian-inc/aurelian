//go:build integration

package recon

import (
	"context"
	"strings"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "github.com/praetorian-inc/aurelian/pkg/modules/aws/recon" // register modules
)

// runFindSecrets runs the find-secrets module with the given args and collects SecretFinding results.
func runFindSecrets(t *testing.T, args map[string]any) []output.SecretFinding {
	t.Helper()

	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "find-secrets")
	if !ok {
		t.Skip("find-secrets module not registered in plugin system")
	}

	cfg := plugin.Config{
		Context: context.Background(),
		Args:    args,
	}
	p1 := pipeline.From(cfg)
	p2 := pipeline.New[model.AurelianModel]()
	pipeline.Pipe(p1, mod.Run, p2)

	results, err := p2.Collect()
	require.NoError(t, err)

	var findings []output.SecretFinding
	for _, r := range results {
		if sf, ok := r.(output.SecretFinding); ok {
			findings = append(findings, sf)
		}
	}
	return findings
}

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
	fixture := testutil.NewFixture(t, "aws/recon/find-secrets")
	fixture.Setup()

	region := fixture.Output("region")
	instanceID := fixture.Output("instance_id")
	testSecret := fixture.Output("test_secret")

	findings := runFindSecrets(t, map[string]any{
		"resource-type": []string{"AWS::EC2::Instance"},
		"regions":       []string{region},
	})

	assert.NotEmpty(t, findings, "expected at least one secret finding from EC2 user data")
	assert.True(t, findingsContainResource(findings, instanceID),
		"expected findings to reference instance ID %s", instanceID)
	assert.True(t, findingsContainSecret(findings, testSecret),
		"expected findings to contain test secret %s", testSecret)
}

func TestFindSecretsLambdaCode(t *testing.T) {
	fixture := testutil.NewFixture(t, "aws/recon/find-secrets")
	fixture.Setup()

	region := fixture.Output("region")
	lambdaFunctionName := fixture.Output("lambda_function_name")
	testSecret := fixture.Output("test_secret")

	findings := runFindSecrets(t, map[string]any{
		"resource-type": []string{"AWS::Lambda::Function"},
		"regions":       []string{region},
	})

	assert.NotEmpty(t, findings, "expected at least one secret finding from Lambda code")
	assert.True(t, findingsContainResource(findings, lambdaFunctionName),
		"expected findings to reference Lambda function %s", lambdaFunctionName)
	assert.True(t, findingsContainSecret(findings, testSecret),
		"expected findings to contain test secret %s", testSecret)
}

func TestFindSecretsCloudFormationTemplate(t *testing.T) {
	fixture := testutil.NewFixture(t, "aws/recon/find-secrets")
	fixture.Setup()

	region := fixture.Output("region")
	stackName := fixture.Output("cloudformation_stack_name")
	testSecret := fixture.Output("test_secret")

	findings := runFindSecrets(t, map[string]any{
		"resource-type": []string{"AWS::CloudFormation::Stack"},
		"regions":       []string{region},
	})

	assert.NotEmpty(t, findings, "expected at least one secret finding from CloudFormation template")
	assert.True(t, findingsContainResource(findings, stackName),
		"expected findings to reference CloudFormation stack %s", stackName)
	assert.True(t, findingsContainSecret(findings, testSecret),
		"expected findings to contain test secret %s", testSecret)
}

func TestFindSecretsCloudWatchLogs(t *testing.T) {
	fixture := testutil.NewFixture(t, "aws/recon/find-secrets")
	fixture.Setup()

	region := fixture.Output("region")
	logGroupName := fixture.Output("log_group_name")
	testSecret := fixture.Output("test_secret")

	findings := runFindSecrets(t, map[string]any{
		"resource-type": []string{"AWS::Logs::LogGroup"},
		"regions":       []string{region},
		"max-events":    100,
		"max-streams":   5,
	})

	assert.NotEmpty(t, findings, "expected at least one secret finding from CloudWatch Logs")
	assert.True(t, findingsContainResource(findings, logGroupName),
		"expected findings to reference log group %s", logGroupName)
	assert.True(t, findingsContainSecret(findings, testSecret),
		"expected findings to contain test secret %s", testSecret)
}
