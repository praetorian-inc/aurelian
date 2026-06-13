package enumeration

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/assert"
)

func TestBuildInstanceResource(t *testing.T) {
	instance := ec2types.Instance{
		InstanceId: aws.String("i-0e2d24b9aec1606c2"),
		State:      &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
		IamInstanceProfile: &ec2types.IamInstanceProfile{
			Arn: aws.String("arn:aws:iam::123456789012:instance-profile/admin-profile"),
		},
	}

	r := buildInstanceResource(instance, "123456789012", "us-east-2")

	assert.Equal(t, "AWS::EC2::Instance", r.ResourceType)
	assert.Equal(t, "i-0e2d24b9aec1606c2", r.ResourceID)
	// ARN form must match the ssm/ec2 instance ResourcePatterns so instance-scoped
	// privesc actions (ec2:ReplaceIamInstanceProfileAssociation) resolve against it.
	assert.Equal(t, "arn:aws:ec2:us-east-2:123456789012:instance/i-0e2d24b9aec1606c2", r.ARN)
	assert.Equal(t, "123456789012", r.AccountRef)
	assert.Equal(t, "us-east-2", r.Region)
	assert.Equal(t, "running", r.Properties["State"])
	assert.Equal(t, "arn:aws:iam::123456789012:instance-profile/admin-profile", r.Properties["IamInstanceProfile"])
	// Instances carry no resource policy.
	assert.Nil(t, r.ResourcePolicy)
}

func TestBuildInstanceResourceNilFields(t *testing.T) {
	instance := ec2types.Instance{
		InstanceId: aws.String("i-abc123"),
	}

	r := buildInstanceResource(instance, "123456789012", "us-west-2")

	assert.Equal(t, "arn:aws:ec2:us-west-2:123456789012:instance/i-abc123", r.ARN)
	assert.Equal(t, "", r.Properties["State"])
	assert.Equal(t, "", r.Properties["IamInstanceProfile"])
}
