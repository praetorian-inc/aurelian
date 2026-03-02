//go:build integration

package recon

import (
	"context"
	"strings"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/model"
	_ "github.com/praetorian-inc/aurelian/pkg/modules/aws/enrichers"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAWSPublicResources(t *testing.T) {
	fixture := testutil.NewFixture(t, "aws/recon/public-resources")
	fixture.Setup()

	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "public-resources")
	if !ok {
		t.Fatal("public-resources module not registered in plugin system")
	}

	cfg := plugin.Config{
		Args: map[string]any{
			"regions": []string{"us-east-1"},
			"resource-type": []string{
				"AWS::S3::Bucket",
				"AWS::SNS::Topic",
				"AWS::SQS::Queue",
				"AWS::Lambda::Function",
				"AWS::EC2::Instance",
				"AWS::EFS::FileSystem",
				"AWS::Cognito::UserPool",
				"AWS::RDS::DBInstance",
			},
		},
		Context: context.Background(),
	}

	p1 := pipeline.From(cfg)
	p2 := pipeline.New[model.AurelianModel]()
	pipeline.Pipe(p1, mod.Run, p2)

	var resources []output.AWSResource
	for m := range p2.Range() {
		if r, ok := m.(output.AWSResource); ok {
			resources = append(resources, r)
		}
	}
	require.NoError(t, p2.Wait())
	require.NotEmpty(t, resources, "should find at least some public resources")

	prefix := fixture.Output("prefix")
	t.Logf("Fixture prefix: %s", prefix)
	t.Logf("Total public resources found: %d", len(resources))
	for _, r := range resources {
		t.Logf("  %s  id=%s  name=%s  arn=%s", r.ResourceType, r.ResourceID, r.DisplayName, r.ARN)
	}

	// resourceMatches checks whether a resource matches any of the given identifiers
	// by checking ARN, ResourceID, and DisplayName fields.
	resourceMatches := func(r output.AWSResource, identifiers ...string) bool {
		for _, id := range identifiers {
			if id != "" && (r.ARN == id || r.ResourceID == id || r.DisplayName == id) {
				return true
			}
		}
		return false
	}

	findResource := func(resourceType string, identifiers ...string) bool {
		for _, r := range resources {
			if r.ResourceType == resourceType && resourceMatches(r, identifiers...) {
				return true
			}
		}
		return false
	}

	// -------------------------------------------------------------------------
	// Policy-based public resources
	// -------------------------------------------------------------------------
	t.Run("S3 bucket with public policy is detected", func(t *testing.T) {
		name := fixture.Output("public_bucket_name")
		assert.True(t, findResource("AWS::S3::Bucket", name),
			"public S3 bucket %s should be detected", name)
	})

	t.Run("SNS topic with public policy is detected", func(t *testing.T) {
		arn := fixture.Output("public_topic_arn")
		assert.True(t, findResource("AWS::SNS::Topic", arn),
			"public SNS topic %s should be detected", arn)
	})

	t.Run("SQS queue with public policy is detected", func(t *testing.T) {
		name := fixture.Output("public_queue_name")
		assert.True(t, findResource("AWS::SQS::Queue", name),
			"public SQS queue %s should be detected", name)
	})

	t.Run("EFS with public policy is detected", func(t *testing.T) {
		id := fixture.Output("public_efs_id")
		assert.True(t, findResource("AWS::EFS::FileSystem", id),
			"public EFS %s should be detected", id)
	})

	// OpenSearch is not yet a supported resource type in the evaluator.
	// t.Run("OpenSearch domain with public policy is detected", ...)

	// -------------------------------------------------------------------------
	// Property-based public resources
	// -------------------------------------------------------------------------
	t.Run("EC2 instance with public IP is detected", func(t *testing.T) {
		id := fixture.Output("public_instance_id")
		assert.True(t, findResource("AWS::EC2::Instance", id),
			"public EC2 instance %s should be detected", id)
	})

	t.Run("RDS instance with public access is detected", func(t *testing.T) {
		id := fixture.Output("public_rds_identifier")
		assert.True(t, findResource("AWS::RDS::DBInstance", id),
			"public RDS instance %s should be detected", id)
	})

	t.Run("Cognito user pool with self-signup is detected", func(t *testing.T) {
		id := fixture.Output("public_cognito_pool_id")
		assert.True(t, findResource("AWS::Cognito::UserPool", id),
			"public Cognito user pool %s should be detected", id)
	})

	// -------------------------------------------------------------------------
	// Lambda variants
	// -------------------------------------------------------------------------
	t.Run("Lambda with function URL (AuthType=NONE) is detected", func(t *testing.T) {
		name := fixture.Output("public_function_name")
		arn := fixture.Output("public_function_arn")
		assert.True(t, findResource("AWS::Lambda::Function", name, arn),
			"Lambda with public function URL %s should be detected", name)
	})

	t.Run("Lambda with public policy and function URL is detected", func(t *testing.T) {
		name := fixture.Output("lambda_policy_and_url_name")
		assert.True(t, findResource("AWS::Lambda::Function", name),
			"Lambda with public policy + URL %s should be detected", name)
	})

	t.Run("Lambda with public policy only is detected", func(t *testing.T) {
		name := fixture.Output("lambda_policy_only_name")
		assert.True(t, findResource("AWS::Lambda::Function", name),
			"Lambda with public policy only %s should be detected", name)
	})

	// -------------------------------------------------------------------------
	// Negative tests: private resources should NOT appear
	// -------------------------------------------------------------------------
	t.Run("Private S3 bucket is not detected", func(t *testing.T) {
		name := fixture.Output("private_bucket_name")
		assert.False(t, findResource("AWS::S3::Bucket", name),
			"private S3 bucket %s should NOT be detected as public", name)
	})

	t.Run("Private Lambda is not detected", func(t *testing.T) {
		name := fixture.Output("lambda_private_name")
		assert.False(t, findResource("AWS::Lambda::Function", name),
			"private Lambda %s should NOT be detected as public", name)
	})

	// -------------------------------------------------------------------------
	// Count regression gate
	// -------------------------------------------------------------------------
	t.Run("Minimum public resource count", func(t *testing.T) {
		fixtureCount := 0
		for _, r := range resources {
			if containsSubstr(r.ARN, prefix) || containsSubstr(r.ResourceID, prefix) || containsSubstr(r.DisplayName, prefix) {
				fixtureCount++
			}
		}
		t.Logf("Fixture public resources: %d", fixtureCount)
		assert.GreaterOrEqual(t, fixtureCount, 7,
			"should detect at least 7 fixture public resources, got %d", fixtureCount)
	})
}

func containsSubstr(s, substr string) bool {
	return substr != "" && strings.Contains(s, substr)
}
