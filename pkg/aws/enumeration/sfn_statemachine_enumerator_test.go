package enumeration

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	"github.com/stretchr/testify/assert"
)

func TestBuildSFNStateMachineResource(t *testing.T) {
	detail := &sfn.DescribeStateMachineOutput{
		Name:            aws.String("orchestrator"),
		StateMachineArn: aws.String("arn:aws:states:us-east-2:123456789012:stateMachine:orchestrator"),
		RoleArn:         aws.String("arn:aws:iam::123456789012:role/sfn-exec-role"),
	}

	r := buildSFNStateMachineResource(detail, "123456789012", "us-east-2")

	assert.Equal(t, "AWS::StepFunctions::StateMachine", r.ResourceType)
	assert.Equal(t, "orchestrator", r.ResourceID)
	assert.Equal(t, "arn:aws:states:us-east-2:123456789012:stateMachine:orchestrator", r.ARN)
	assert.Equal(t, "123456789012", r.AccountRef)
	assert.Equal(t, "us-east-2", r.Region)
	// RoleArn must be captured so resource_service_role.yaml can substring-match it
	// inside the flattened properties JSON string and create the HAS_ROLE edge.
	assert.Equal(t, "arn:aws:iam::123456789012:role/sfn-exec-role", r.Properties["RoleArn"])
	// State machines carry no resource policy.
	assert.Nil(t, r.ResourcePolicy)
}

func TestBuildSFNStateMachineResourceNilArn(t *testing.T) {
	// A missing ARN must not panic; the ARN falls back to a synthesized form.
	detail := &sfn.DescribeStateMachineOutput{
		Name:    aws.String("no-arn-sm"),
		RoleArn: aws.String("arn:aws:iam::123456789012:role/sfn-exec-role"),
	}

	r := buildSFNStateMachineResource(detail, "123456789012", "eu-west-1")

	assert.Equal(t, "arn:aws:states:eu-west-1:123456789012:stateMachine:no-arn-sm", r.ARN)
	assert.Equal(t, "no-arn-sm", r.ResourceID)
	assert.Equal(t, "arn:aws:iam::123456789012:role/sfn-exec-role", r.Properties["RoleArn"])
}
