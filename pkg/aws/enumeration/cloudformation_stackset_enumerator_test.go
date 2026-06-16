package enumeration

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	cfntypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/stretchr/testify/assert"
)

func TestBuildStackSetResource(t *testing.T) {
	stackSet := &cfntypes.StackSet{
		StackSetName:          aws.String("org-baseline"),
		StackSetARN:           aws.String("arn:aws:cloudformation:us-east-2:123456789012:stackset/org-baseline:abc-123"),
		AdministrationRoleARN: aws.String("arn:aws:iam::123456789012:role/AWSCloudFormationStackSetAdministrationRole"),
		ExecutionRoleName:     aws.String("AWSCloudFormationStackSetExecutionRole"),
	}

	r := buildStackSetResource(stackSet, "123456789012", "us-east-2")

	assert.Equal(t, "AWS::CloudFormation::StackSet", r.ResourceType)
	assert.Equal(t, "org-baseline", r.ResourceID)
	assert.Equal(t, "arn:aws:cloudformation:us-east-2:123456789012:stackset/org-baseline:abc-123", r.ARN)
	assert.Equal(t, "123456789012", r.AccountRef)
	assert.Equal(t, "us-east-2", r.Region)
	// AdministrationRoleARN must be captured so resource_service_role.yaml can substring-match
	// it inside the flattened properties JSON string and create the HAS_ROLE edge.
	assert.Equal(t, "arn:aws:iam::123456789012:role/AWSCloudFormationStackSetAdministrationRole", r.Properties["AdministrationRoleARN"])
	// ExecutionRoleName is a NAME, not an ARN; captured for completeness but never matches a role ARN.
	assert.Equal(t, "AWSCloudFormationStackSetExecutionRole", r.Properties["ExecutionRoleName"])
	// Stack sets carry no resource policy.
	assert.Nil(t, r.ResourcePolicy)
}

func TestBuildStackSetResourceNoRole(t *testing.T) {
	// A service-managed stack set has no administration role — fail-closed: no ARN to match, no edge.
	stackSet := &cfntypes.StackSet{
		StackSetName: aws.String("service-managed"),
		StackSetARN:  aws.String("arn:aws:cloudformation:us-west-2:123456789012:stackset/service-managed:def-456"),
	}

	r := buildStackSetResource(stackSet, "123456789012", "us-west-2")

	assert.Equal(t, "service-managed", r.ResourceID)
	assert.Equal(t, "", r.Properties["AdministrationRoleARN"])
	assert.Equal(t, "", r.Properties["ExecutionRoleName"])
}

func TestBuildStackSetResourceNilArn(t *testing.T) {
	// A missing ARN must not panic; the ARN falls back to a synthesized form.
	stackSet := &cfntypes.StackSet{
		StackSetName:          aws.String("no-arn-ss"),
		AdministrationRoleARN: aws.String("arn:aws:iam::123456789012:role/admin-role"),
	}

	r := buildStackSetResource(stackSet, "123456789012", "eu-west-1")

	assert.Equal(t, "arn:aws:cloudformation:eu-west-1:123456789012:stackset/no-arn-ss", r.ARN)
	assert.Equal(t, "no-arn-ss", r.ResourceID)
	assert.Equal(t, "arn:aws:iam::123456789012:role/admin-role", r.Properties["AdministrationRoleARN"])
}
