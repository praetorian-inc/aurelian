package aws

import (
	"context"
	"fmt"

	"github.com/praetorian-inc/aurelian/pkg/links/aws/base"
)

// CDKRoleInfo represents a detected CDK role
type CDKRoleInfo struct {
	RoleName      string `json:"role_name"`
	RoleArn       string `json:"role_arn"`
	Qualifier     string `json:"qualifier"`
	Region        string `json:"region"`
	AccountID     string `json:"account_id"`
	CreationDate  string `json:"creation_date"`
	RoleType      string `json:"role_type"`
	BucketName    string `json:"expected_bucket_name"`
	TrustPolicy   string `json:"trust_policy,omitempty"`
	AssumeRoleDoc string `json:"assume_role_policy_document,omitempty"`
}


// ComputeBucketName generates the expected CDK assets bucket name from the role info
func (r *CDKRoleInfo) ComputeBucketName() string {
	if r.Qualifier == "" || r.AccountID == "" || r.Region == "" {
		return ""
	}
	return fmt.Sprintf("cdk-%s-assets-%s-%s", r.Qualifier, r.AccountID, r.Region)
}

type AwsCdkRoleDetector struct {
	*base.NativeAWSLink
}

func NewAwsCdkRoleDetector(args map[string]any) *AwsCdkRoleDetector {
	return &AwsCdkRoleDetector{
		NativeAWSLink: base.NewNativeAWSLink("AWS CDK Role Detector", args),
	}
}

func (l *AwsCdkRoleDetector) Process(ctx context.Context, input any) ([]any, error) {
	// TODO: Port full CDK role detection logic after Janus removal
	l.Logger().Info("AwsCdkRoleDetector.Process not yet fully implemented - requires Janus removal")
	return l.Outputs(), nil
}

// Stub helper methods to maintain interface compatibility
