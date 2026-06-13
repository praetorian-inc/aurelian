package enumeration

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	cfntypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/stretchr/testify/assert"
)

func TestBuildStackResource(t *testing.T) {
	stack := cfntypes.Stack{
		StackName:   aws.String("my-stack"),
		StackId:     aws.String("arn:aws:cloudformation:us-east-2:123456789012:stack/my-stack/abc-123"),
		StackStatus: cfntypes.StackStatusCreateComplete,
		RoleARN:     aws.String("arn:aws:iam::123456789012:role/stack-service-role"),
	}

	r := buildStackResource(stack, "123456789012", "us-east-2")

	assert.Equal(t, "AWS::CloudFormation::Stack", r.ResourceType)
	assert.Equal(t, "my-stack", r.ResourceID)
	// StackId is a full ARN and is used verbatim so the node keys on the real stack ARN.
	assert.Equal(t, "arn:aws:cloudformation:us-east-2:123456789012:stack/my-stack/abc-123", r.ARN)
	assert.Equal(t, "123456789012", r.AccountRef)
	assert.Equal(t, "us-east-2", r.Region)
	assert.Equal(t, "CREATE_COMPLETE", r.Properties["StackStatus"])
	// RoleARN must be captured so resource_service_role.yaml can substring-match it
	// inside the flattened properties JSON string and create the HAS_ROLE edge.
	assert.Equal(t, "arn:aws:iam::123456789012:role/stack-service-role", r.Properties["RoleARN"])
	// Stacks carry no resource policy.
	assert.Nil(t, r.ResourcePolicy)
}

func TestBuildStackResourceNoRole(t *testing.T) {
	// A roleless stack (runs as the caller's creds) emits an empty RoleARN, which is the
	// fail-closed case: resource_service_role.yaml will not match an empty string to any
	// role ARN, so no HAS_ROLE edge is created (correct — no inherited role to escalate to).
	stack := cfntypes.Stack{
		StackName: aws.String("roleless"),
		StackId:   aws.String("arn:aws:cloudformation:us-west-2:123456789012:stack/roleless/def-456"),
	}

	r := buildStackResource(stack, "123456789012", "us-west-2")

	assert.Equal(t, "arn:aws:cloudformation:us-west-2:123456789012:stack/roleless/def-456", r.ARN)
	assert.Equal(t, "", r.Properties["RoleARN"])
	assert.Equal(t, "", r.Properties["StackStatus"])
}

func TestBuildStackResourceNilStackId(t *testing.T) {
	// DescribeStacks always returns StackId, but guard nil-safety: a missing StackId
	// falls back to a synthesized ARN so the node still keys cleanly.
	stack := cfntypes.Stack{
		StackName: aws.String("no-id"),
	}

	r := buildStackResource(stack, "123456789012", "eu-west-1")

	assert.Equal(t, "arn:aws:cloudformation:eu-west-1:123456789012:stack/no-id", r.ARN)
	assert.Equal(t, "no-id", r.ResourceID)
	assert.Equal(t, "", r.Properties["RoleARN"])
}
