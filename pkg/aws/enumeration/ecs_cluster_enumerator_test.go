package enumeration

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/stretchr/testify/assert"
)

func TestBuildECSClusterResource(t *testing.T) {
	c := &ecstypes.Cluster{
		ClusterName: aws.String("prod-cluster"),
		ClusterArn:  aws.String("arn:aws:ecs:us-east-2:123456789012:cluster/prod-cluster"),
		Status:      aws.String("ACTIVE"),
	}

	r := buildECSClusterResource(c, "123456789012", "us-east-2")

	assert.Equal(t, "AWS::ECS::Cluster", r.ResourceType)
	assert.Equal(t, "prod-cluster", r.ResourceID)
	assert.Equal(t, "arn:aws:ecs:us-east-2:123456789012:cluster/prod-cluster", r.ARN)
	assert.Equal(t, "123456789012", r.AccountRef)
	assert.Equal(t, "us-east-2", r.Region)
	assert.Equal(t, "prod-cluster", r.DisplayName)
	assert.Equal(t, "prod-cluster", r.Properties["ClusterName"])
	assert.Equal(t, "ACTIVE", r.Properties["Status"])
	// Clusters carry no IAM role and no resource policy.
	assert.Nil(t, r.ResourcePolicy)
}

func TestBuildECSClusterResourceNameFromARN(t *testing.T) {
	// DescribeClusters omitted ClusterName: the name is recovered from the ARN so the
	// ResourceID still matches the cluster/<name> scope an attacker policy targets.
	c := &ecstypes.Cluster{
		ClusterArn: aws.String("arn:aws:ecs:eu-west-1:123456789012:cluster/inferred-name"),
	}

	r := buildECSClusterResource(c, "123456789012", "eu-west-1")

	assert.Equal(t, "inferred-name", r.ResourceID)
	assert.Equal(t, "inferred-name", r.Properties["ClusterName"])
	assert.Equal(t, "arn:aws:ecs:eu-west-1:123456789012:cluster/inferred-name", r.ARN)
	assert.Equal(t, "", r.Properties["Status"])
}

func TestBuildECSClusterResourceNilArn(t *testing.T) {
	// A missing ARN must not panic; the ARN falls back to a synthesized form keyed on the name.
	c := &ecstypes.Cluster{
		ClusterName: aws.String("no-arn-cluster"),
	}

	r := buildECSClusterResource(c, "123456789012", "us-west-2")

	assert.Equal(t, "no-arn-cluster", r.ResourceID)
	assert.Equal(t, "arn:aws:ecs:us-west-2:123456789012:cluster/no-arn-cluster", r.ARN)
	assert.Equal(t, "no-arn-cluster", r.Properties["ClusterName"])
}

func TestBuildECSClusterResourceEmptyFields(t *testing.T) {
	// All-empty cluster: no panic, empty ID/ARN, empty property values.
	c := &ecstypes.Cluster{}

	r := buildECSClusterResource(c, "123456789012", "us-east-1")

	assert.Equal(t, "AWS::ECS::Cluster", r.ResourceType)
	assert.Equal(t, "", r.ResourceID)
	assert.Equal(t, "", r.ARN)
	assert.Equal(t, "", r.Properties["ClusterName"])
	assert.Equal(t, "", r.Properties["Status"])
}
