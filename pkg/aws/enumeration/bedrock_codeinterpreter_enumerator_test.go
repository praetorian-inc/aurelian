package enumeration

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	bedrockcc "github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol"
	bedrocktypes "github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol/types"
	"github.com/stretchr/testify/assert"
)

func TestBuildCodeInterpreterResource(t *testing.T) {
	detail := &bedrockcc.GetCodeInterpreterOutput{
		CodeInterpreterId:  aws.String("ci-abc123"),
		CodeInterpreterArn: aws.String("arn:aws:bedrock-agentcore:us-east-1:123456789012:code-interpreter/ci-abc123"),
		Name:               aws.String("analytics-ci"),
		Status:             bedrocktypes.CodeInterpreterStatusReady,
		ExecutionRoleArn:   aws.String("arn:aws:iam::123456789012:role/ci-exec-role"),
	}

	r := buildCodeInterpreterResource(detail, "123456789012", "us-east-1")

	assert.Equal(t, "AWS::BedrockAgentCore::CodeInterpreter", r.ResourceType)
	assert.Equal(t, "ci-abc123", r.ResourceID)
	assert.Equal(t, "arn:aws:bedrock-agentcore:us-east-1:123456789012:code-interpreter/ci-abc123", r.ARN)
	assert.Equal(t, "123456789012", r.AccountRef)
	assert.Equal(t, "us-east-1", r.Region)
	assert.Equal(t, "READY", r.Properties["Status"])
	// ExecutionRoleArn must be captured so resource_service_role.yaml can substring-match
	// it inside the flattened properties JSON string and create the HAS_ROLE edge.
	assert.Equal(t, "arn:aws:iam::123456789012:role/ci-exec-role", r.Properties["ExecutionRoleArn"])
	// Code interpreters carry no resource policy.
	assert.Nil(t, r.ResourcePolicy)
}

func TestBuildCodeInterpreterResourceNoRole(t *testing.T) {
	// A code interpreter with no execution role emits an empty ExecutionRoleArn, the
	// fail-closed case: resource_service_role.yaml will not match an empty string to any
	// role ARN, so no HAS_ROLE edge is created.
	detail := &bedrockcc.GetCodeInterpreterOutput{
		CodeInterpreterId:  aws.String("ci-noroleid"),
		CodeInterpreterArn: aws.String("arn:aws:bedrock-agentcore:us-west-2:123456789012:code-interpreter/ci-noroleid"),
	}

	r := buildCodeInterpreterResource(detail, "123456789012", "us-west-2")

	assert.Equal(t, "ci-noroleid", r.ResourceID)
	assert.Equal(t, "", r.Properties["ExecutionRoleArn"])
}

func TestBuildCodeInterpreterResourceNilArn(t *testing.T) {
	// A missing ARN must not panic; the ARN falls back to a synthesized form.
	detail := &bedrockcc.GetCodeInterpreterOutput{
		CodeInterpreterId: aws.String("ci-noarn"),
	}

	r := buildCodeInterpreterResource(detail, "123456789012", "eu-west-1")

	assert.Equal(t, "arn:aws:bedrock-agentcore:eu-west-1:123456789012:code-interpreter/ci-noarn", r.ARN)
	assert.Equal(t, "ci-noarn", r.ResourceID)
	assert.Equal(t, "", r.Properties["ExecutionRoleArn"])
}
