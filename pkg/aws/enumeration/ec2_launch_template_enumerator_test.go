package enumeration

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/assert"
)

func TestBuildLaunchTemplateResourceARNProfile(t *testing.T) {
	tmpl := ec2types.LaunchTemplate{
		LaunchTemplateId:   aws.String("lt-0abc123"),
		LaunchTemplateName: aws.String("pl-prod-lt-005"),
	}
	profileARN := "arn:aws:iam::123456789012:instance-profile/pl-prod-lt-005-profile"

	r := buildLaunchTemplateResource(tmpl, profileARN, "123456789012", "us-east-1")

	assert.Equal(t, "AWS::EC2::LaunchTemplate", r.ResourceType)
	assert.Equal(t, "lt-0abc123", r.ResourceID)
	assert.Equal(t, "arn:aws:ec2:us-east-1:123456789012:launch-template/lt-0abc123", r.ARN)
	assert.Equal(t, "123456789012", r.AccountRef)
	assert.Equal(t, "us-east-1", r.Region)
	assert.Equal(t, "pl-prod-lt-005", r.DisplayName)
	// IamInstanceProfile is the property set_launch_template_role.yaml matches against the
	// role's InstanceProfileList (ARN form) to create the HAS_ROLE edge.
	assert.Equal(t, profileARN, r.Properties["IamInstanceProfile"])
}

func TestBuildLaunchTemplateResourceNameProfile(t *testing.T) {
	tmpl := ec2types.LaunchTemplate{
		LaunchTemplateId:   aws.String("lt-0def456"),
		LaunchTemplateName: aws.String("pl-prod-lt-006"),
	}

	r := buildLaunchTemplateResource(tmpl, "pl-prod-lt-006-profile", "123456789012", "us-west-2")

	assert.Equal(t, "lt-0def456", r.ResourceID)
	// Name form: set_launch_template_role.yaml matches the bare profile name (account-scoped).
	assert.Equal(t, "pl-prod-lt-006-profile", r.Properties["IamInstanceProfile"])
}

func TestBuildLaunchTemplateResourceNoProfile(t *testing.T) {
	// A template whose default version binds no instance profile emits an empty
	// IamInstanceProfile (fail-closed): set_launch_template_role.yaml excludes the empty
	// string outright so no HAS_ROLE edge is created. The resource is still emitted.
	tmpl := ec2types.LaunchTemplate{
		LaunchTemplateId:   aws.String("lt-0noprofile"),
		LaunchTemplateName: aws.String("pl-noprofile"),
	}

	r := buildLaunchTemplateResource(tmpl, "", "123456789012", "us-east-1")

	assert.Equal(t, "AWS::EC2::LaunchTemplate", r.ResourceType)
	assert.Equal(t, "lt-0noprofile", r.ResourceID)
	assert.Equal(t, "", r.Properties["IamInstanceProfile"])
}
