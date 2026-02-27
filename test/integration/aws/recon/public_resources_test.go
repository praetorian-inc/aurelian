//go:build integration

package recon

import (
	"context"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	// Register modules and enrichers
	_ "github.com/praetorian-inc/aurelian/pkg/modules/aws/enrichers"
	_ "github.com/praetorian-inc/aurelian/pkg/modules/aws/recon"
)

func TestPublicResources(t *testing.T) {
	fixture := testutil.NewFixture(t, "aws/recon/public-resources")
	fixture.Setup()

	publicBucket := fixture.Output("public_bucket_name")
	privateBucket := fixture.Output("private_bucket_name")
	topicARN := fixture.Output("public_topic_arn")
	functionARN := fixture.Output("public_function_arn")
	instanceID := fixture.Output("public_instance_id")
	efsID := fixture.Output("public_efs_id")
	cognitoPoolID := fixture.Output("public_cognito_pool_id")
	rdsIdentifier := fixture.Output("public_rds_identifier")
	opensearchDomain := fixture.Output("public_opensearch_domain")
	prefix := fixture.Output("prefix")

	t.Logf("Testing with prefix: %s", prefix)
	t.Logf("Public bucket: %s, Private bucket: %s", publicBucket, privateBucket)
	t.Logf("Topic ARN: %s, Function ARN: %s", topicARN, functionARN)
	t.Logf("Instance: %s, EFS: %s, Cognito: %s", instanceID, efsID, cognitoPoolID)
	t.Logf("RDS: %s, OpenSearch: %s", rdsIdentifier, opensearchDomain)

	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "public-resources")
	if !ok {
		t.Fatal("public-resources module not registered")
	}

	cfg := plugin.Config{
		Context: context.Background(),
		Args: map[string]any{
			"regions": []string{"us-east-1"},
		},
	}
	p1 := pipeline.From(cfg)
	p2 := pipeline.New[model.AurelianModel]()
	pipeline.Pipe(p1, mod.Run, p2)

	results, err := p2.Collect()
	require.NoError(t, err, "module run should succeed")

	if len(results) == 0 {
		t.Fatal("expected at least one result")
	}

	// Extract AWSResource instances from results
	var resources []output.AWSResource
	for _, r := range results {
		if ar, ok := r.(output.AWSResource); ok {
			resources = append(resources, ar)
		}
	}

	t.Logf("Found %d public resources", len(resources))
	for _, r := range resources {
		t.Logf("  %s: %s", r.ResourceType, r.ResourceID)
	}

	// Helper to check if a resource type + identifier is in results
	findResource := func(resourceType, identifier string) bool {
		for _, r := range resources {
			if r.ResourceType == resourceType {
				if r.ResourceID == identifier {
					return true
				}
				// Also check common property fields
				for _, v := range r.Properties {
					if s, ok := v.(string); ok && s == identifier {
						return true
					}
				}
			}
		}
		return false
	}

	// Verify policy-based public resources
	t.Run("S3_Public_Bucket", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, publicBucket)
	})

	t.Run("SNS_Public_Topic", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, topicARN)
	})

	t.Run("SQS_Public_Queue", func(t *testing.T) {
		found := false
		for _, r := range resources {
			if r.ResourceType == "AWS::SQS::Queue" {
				found = true
				break
			}
		}
		assert.True(t, found, "should find public SQS queue")
	})

	t.Run("Lambda_Public_FunctionURL", func(t *testing.T) {
		found := false
		for _, r := range resources {
			if r.ResourceType == "AWS::Lambda::Function" {
				found = true
				break
			}
		}
		assert.True(t, found, "should find Lambda with public function URL")
	})

	t.Run("EFS_Public_FileSystem", func(t *testing.T) {
		found := findResource("AWS::EFS::FileSystem", efsID)
		assert.True(t, found, "should find public EFS file system %s", efsID)
	})

	t.Run("OpenSearch_Public_Domain", func(t *testing.T) {
		t.Skip("OpenSearch domains do not support CloudControl LIST action")
	})

	// Verify property-based public resources
	t.Run("EC2_Public_Instance", func(t *testing.T) {
		found := findResource("AWS::EC2::Instance", instanceID)
		assert.True(t, found, "should find EC2 instance with public IP %s", instanceID)
	})

	t.Run("Cognito_Public_UserPool", func(t *testing.T) {
		found := findResource("AWS::Cognito::UserPool", cognitoPoolID)
		assert.True(t, found, "should find Cognito user pool with self-signup %s", cognitoPoolID)
	})

	t.Run("RDS_Public_Instance", func(t *testing.T) {
		found := findResource("AWS::RDS::DBInstance", rdsIdentifier)
		assert.True(t, found, "should find publicly accessible RDS instance %s", rdsIdentifier)
	})

	// Verify private bucket is NOT in results
	t.Run("S3_Private_Bucket_Excluded", func(t *testing.T) {
		for _, r := range resources {
			if r.ResourceType == "AWS::S3::Bucket" {
				name, _ := r.Properties["BucketName"].(string)
				if name == privateBucket {
					t.Errorf("private bucket %s should not appear in public resources results", privateBucket)
				}
			}
		}
	})

	// Check minimum results - we should have at least 1 public resource
	testutil.AssertMinResults(t, results, 1)
}
