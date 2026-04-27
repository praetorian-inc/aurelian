package enumeration

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	configtypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	"github.com/stretchr/testify/assert"
)

func TestConfigIdentifierTranslate(t *testing.T) {
	trans := newConfigIdentifier()

	cases := []struct {
		name         string
		resourceType string
		rec          configtypes.ResourceIdentifier
		accountID    string
		region       string
		wantID       string
		wantOK       bool
	}{
		{
			name:         "heuristic_name_present",
			resourceType: "AWS::S3::Bucket",
			rec:          configtypes.ResourceIdentifier{ResourceName: aws.String("my-bucket"), ResourceId: aws.String("should-not-be-returned")},
			wantID:       "my-bucket",
			wantOK:       true,
		},
		{
			name:         "heuristic_name_empty_fallback_to_id",
			resourceType: "AWS::EC2::Instance",
			rec:          configtypes.ResourceIdentifier{ResourceId: aws.String("i-abc123")},
			wantID:       "i-abc123",
			wantOK:       true,
		},
		{
			name:         "heuristic_both_empty",
			resourceType: "AWS::S3::Bucket",
			rec:          configtypes.ResourceIdentifier{},
			wantID:       "",
			wantOK:       false,
		},
		{
			name:         "override_cloudformation_stack_returns_name",
			resourceType: "AWS::CloudFormation::Stack",
			rec: configtypes.ResourceIdentifier{
				ResourceId:   aws.String("arn:aws:cloudformation:us-east-1:123456789012:stack/my-stack/abcd"),
				ResourceName: aws.String("my-stack"),
			},
			wantID: "my-stack",
			wantOK: true,
		},
		{
			name:         "override_cloudformation_stack_name_missing",
			resourceType: "AWS::CloudFormation::Stack",
			rec:          configtypes.ResourceIdentifier{ResourceId: aws.String("arn:aws:cloudformation:...:stack/my-stack/abcd")},
			wantID:       "",
			wantOK:       false,
		},
		{
			name:         "override_amplify_app_returns_id",
			resourceType: "AWS::Amplify::App",
			rec: configtypes.ResourceIdentifier{
				ResourceId:   aws.String("d1abcxyz"),
				ResourceName: aws.String("my-app"),
			},
			wantID: "d1abcxyz",
			wantOK: true,
		},
		{
			name:         "override_amplify_app_id_missing",
			resourceType: "AWS::Amplify::App",
			rec:          configtypes.ResourceIdentifier{ResourceName: aws.String("my-app")},
			wantID:       "",
			wantOK:       false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := trans.Translate(tc.resourceType, tc.rec, tc.accountID, tc.region)
			assert.Equal(t, tc.wantOK, ok)
			assert.Equal(t, tc.wantID, got)
		})
	}
}
