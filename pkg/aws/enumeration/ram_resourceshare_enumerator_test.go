package enumeration

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ramtypes "github.com/aws/aws-sdk-go-v2/service/ram/types"
	"github.com/stretchr/testify/assert"
)

func TestBuildResourceShareResource_External(t *testing.T) {
	share := ramtypes.ResourceShare{
		ResourceShareArn:        aws.String("arn:aws:ram:us-east-1:123456789012:resource-share/abc-123"),
		Name:                    aws.String("shared-tgw"),
		OwningAccountId:         aws.String("123456789012"),
		AllowExternalPrincipals: aws.Bool(true),
		Status:                  ramtypes.ResourceShareStatusActive,
		FeatureSet:              ramtypes.ResourceShareFeatureSetStandard,
	}

	r := buildResourceShareResource(
		share,
		[]string{"210987654321"},
		[]string{"arn:aws:ec2:us-east-1:123456789012:transit-gateway/tgw-0abc"},
		"123456789012", "us-east-1",
	)

	assert.Equal(t, "AWS::RAM::ResourceShare", r.ResourceType)
	assert.Equal(t, "arn:aws:ram:us-east-1:123456789012:resource-share/abc-123", r.ARN)
	assert.Equal(t, "arn:aws:ram:us-east-1:123456789012:resource-share/abc-123", r.ResourceID)
	assert.Equal(t, "123456789012", r.AccountRef)
	assert.Equal(t, "us-east-1", r.Region)
	assert.Equal(t, "shared-tgw", r.DisplayName)
	assert.Equal(t, true, r.Properties["AllowExternalPrincipals"])
	assert.Equal(t, "ACTIVE", r.Properties["Status"])
	assert.Equal(t, "STANDARD", r.Properties["FeatureSet"])
	assert.Equal(t, []string{"210987654321"}, r.Properties["Principals"])
	assert.Equal(t, []string{"arn:aws:ec2:us-east-1:123456789012:transit-gateway/tgw-0abc"}, r.Properties["ResourceArns"])
}

func TestBuildResourceShareResource_OrgOnlyNilFields(t *testing.T) {
	// A share with AllowExternalPrincipals=false and no associations must not panic
	// and must report AllowExternalPrincipals=false with empty principal/resource lists.
	share := ramtypes.ResourceShare{
		ResourceShareArn:        aws.String("arn:aws:ram:us-west-2:123456789012:resource-share/def-456"),
		Name:                    aws.String("org-subnet-share"),
		OwningAccountId:         aws.String("123456789012"),
		AllowExternalPrincipals: aws.Bool(false),
		Status:                  ramtypes.ResourceShareStatusActive,
	}

	r := buildResourceShareResource(share, nil, nil, "123456789012", "us-west-2")

	assert.Equal(t, false, r.Properties["AllowExternalPrincipals"])
	assert.Equal(t, "org-subnet-share", r.DisplayName)
	assert.Empty(t, r.Properties["Principals"])
	assert.Empty(t, r.Properties["ResourceArns"])
}

func TestBuildResourceShareResource_MissingArnFallsBackToAccountID(t *testing.T) {
	// OwningAccountId absent → AccountRef falls back to the caller-supplied accountID.
	share := ramtypes.ResourceShare{
		ResourceShareArn:        aws.String("arn:aws:ram:eu-west-1:999999999999:resource-share/ghi-789"),
		Name:                    aws.String("no-owner-field"),
		AllowExternalPrincipals: aws.Bool(true),
	}

	r := buildResourceShareResource(share, nil, nil, "111111111111", "eu-west-1")

	assert.Equal(t, "111111111111", r.AccountRef)
}
