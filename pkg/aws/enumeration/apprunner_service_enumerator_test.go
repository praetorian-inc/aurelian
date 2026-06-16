package enumeration

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	apprunnertypes "github.com/aws/aws-sdk-go-v2/service/apprunner/types"
	"github.com/stretchr/testify/assert"
)

func TestBuildAppRunnerServiceResource(t *testing.T) {
	service := &apprunnertypes.Service{
		ServiceName: aws.String("web-svc"),
		ServiceId:   aws.String("svc-abc123"),
		ServiceArn:  aws.String("arn:aws:apprunner:us-east-2:123456789012:service/web-svc/svc-abc123"),
		InstanceConfiguration: &apprunnertypes.InstanceConfiguration{
			InstanceRoleArn: aws.String("arn:aws:iam::123456789012:role/apprunner-instance-role"),
		},
	}

	r := buildAppRunnerServiceResource(service, "123456789012", "us-east-2")

	assert.Equal(t, "AWS::AppRunner::Service", r.ResourceType)
	assert.Equal(t, "web-svc", r.ResourceID)
	assert.Equal(t, "arn:aws:apprunner:us-east-2:123456789012:service/web-svc/svc-abc123", r.ARN)
	assert.Equal(t, "123456789012", r.AccountRef)
	assert.Equal(t, "us-east-2", r.Region)
	// InstanceRoleArn must be captured so resource_service_role.yaml can substring-match it
	// inside the flattened properties JSON string and create the HAS_ROLE edge.
	assert.Equal(t, "arn:aws:iam::123456789012:role/apprunner-instance-role", r.Properties["InstanceRoleArn"])
	// App Runner services carry no resource policy.
	assert.Nil(t, r.ResourcePolicy)
}

func TestBuildAppRunnerServiceResourceNilInstanceConfig(t *testing.T) {
	// A service with no InstanceConfiguration must not panic and emits an empty role
	// (the default App Runner instance role is implicit, not surfaced — fail-closed).
	service := &apprunnertypes.Service{
		ServiceName: aws.String("no-config-svc"),
		ServiceId:   aws.String("svc-noconfig"),
		ServiceArn:  aws.String("arn:aws:apprunner:us-west-2:123456789012:service/no-config-svc/svc-noconfig"),
	}

	r := buildAppRunnerServiceResource(service, "123456789012", "us-west-2")

	assert.Equal(t, "no-config-svc", r.ResourceID)
	assert.Equal(t, "", r.Properties["InstanceRoleArn"])
}

func TestBuildAppRunnerServiceResourceNilArn(t *testing.T) {
	// A missing ARN must not panic; the ARN falls back to a synthesized form.
	service := &apprunnertypes.Service{
		ServiceName: aws.String("no-arn-svc"),
		ServiceId:   aws.String("svc-noarn"),
	}

	r := buildAppRunnerServiceResource(service, "123456789012", "eu-west-1")

	assert.Equal(t, "arn:aws:apprunner:eu-west-1:123456789012:service/no-arn-svc/svc-noarn", r.ARN)
	assert.Equal(t, "", r.Properties["InstanceRoleArn"])
}
