package enumeration

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestNewEnumerator_RegistersSFNStateMachine(t *testing.T) {
	e := NewEnumerator(plugin.AWSCommonRecon{Regions: []string{"us-east-1"}, Concurrency: 1})
	defer func() { _ = e.Close() }()

	enum, ok := e.enumerators["AWS::StepFunctions::StateMachine"]
	if !ok {
		t.Fatal("expected AWS::StepFunctions::StateMachine to be registered on the dispatcher")
	}
	if got := enum.ResourceType(); got != "AWS::StepFunctions::StateMachine" {
		t.Errorf("registered enumerator ResourceType() = %q, want AWS::StepFunctions::StateMachine", got)
	}
}

func TestSFNStateMachineEnumerator_EnumerateByARN_Errors(t *testing.T) {
	provider := NewAWSConfigProvider(plugin.AWSCommonRecon{})
	enum := NewSFNStateMachineEnumerator(plugin.AWSCommonRecon{}, provider, NewSkipReport())
	out := pipeline.New[output.AWSResource]()

	t.Run("bad ARN returns error", func(t *testing.T) {
		err := enum.EnumerateByARN("not-an-arn", out)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parse ARN")
	})

	t.Run("non-stateMachine resource returns error", func(t *testing.T) {
		err := enum.EnumerateByARN("arn:aws:states:us-east-1:123456789012:activity:myActivity", out)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid step functions state machine ARN resource")
	})

	t.Run("ARN missing region returns error", func(t *testing.T) {
		err := enum.EnumerateByARN("arn:aws:states::123456789012:stateMachine:myMachine", out)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing region")
	})
}
