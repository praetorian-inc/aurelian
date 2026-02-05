package aws

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/praetorian-inc/aurelian/pkg/links/aws/base"
	"github.com/praetorian-inc/aurelian/pkg/output"
)

// CDKBootstrapInfo represents CDK bootstrap version information
type CDKBootstrapInfo struct {
	AccountID string `json:"account_id"`
	Region    string `json:"region"`
	Qualifier string `json:"qualifier"`
	Version   int    `json:"version"`
	HasVersion bool  `json:"has_version"`
	AccessDenied bool `json:"access_denied"` // True if we got permission denied, not missing parameter
}

type AwsCdkBootstrapChecker struct {
	*base.NativeAWSLink
}

func NewAwsCdkBootstrapChecker(args map[string]any) *AwsCdkBootstrapChecker {
	return &AwsCdkBootstrapChecker{
		NativeAWSLink: base.NewNativeAWSLink("cdk-bootstrap-checker", args),
	}
}

func (l *AwsCdkBootstrapChecker) Process(ctx context.Context, input any) ([]any, error) {
	// Try to extract CDKRoleInfo from input
	cdkRole, ok := input.(CDKRoleInfo)
	if !ok {
		return nil, fmt.Errorf("input is not CDKRoleInfo, got %T", input)
	}

	awsConfig, err := l.GetConfig(ctx, cdkRole.Region)
	if err != nil {
		l.Send(cdkRole) // Pass through even if we can't check version
		return l.Outputs(), nil
	}

	ssmClient := ssm.NewFromConfig(awsConfig)

	// Check CDK bootstrap version from SSM parameter
	bootstrapInfo := l.checkBootstrapVersion(ctx, ssmClient, cdkRole.AccountID, cdkRole.Region, cdkRole.Qualifier)

	// Generate risk if version is too old or missing
	if risk := l.generateBootstrapVersionRisk(cdkRole, bootstrapInfo); risk != nil {
		l.Send(*risk)
	}

	// Pass through the original role info for other links
	l.Send(cdkRole)
	return l.Outputs(), nil
}

func (l *AwsCdkBootstrapChecker) checkBootstrapVersion(ctx context.Context, ssmClient *ssm.Client, accountID, region, qualifier string) CDKBootstrapInfo {
	parameterName := fmt.Sprintf("/cdk-bootstrap/%s/version", qualifier)

	result, err := ssmClient.GetParameter(ctx, &ssm.GetParameterInput{
		Name: &parameterName,
	})
	
	bootstrapInfo := CDKBootstrapInfo{
		AccountID: accountID,
		Region:    region,
		Qualifier: qualifier,
		HasVersion: false,
		AccessDenied: false,
	}
	
	if err != nil {
		// Check if this is a permission error vs parameter not found
		if isAccessDeniedError(err) {
			bootstrapInfo.AccessDenied = true
		} else if isParameterNotFoundError(err) {
			// HasVersion remains false for truly missing parameters
		}
		return bootstrapInfo
	}

	if result.Parameter != nil && result.Parameter.Value != nil {
		if version, err := strconv.Atoi(*result.Parameter.Value); err == nil {
			bootstrapInfo.Version = version
			bootstrapInfo.HasVersion = true
		}
	}
	
	return bootstrapInfo
}

func (l *AwsCdkBootstrapChecker) generateBootstrapVersionRisk(cdkRole CDKRoleInfo, bootstrapInfo CDKBootstrapInfo) *output.Risk {
	// Don't generate false positives for permission errors
	if bootstrapInfo.AccessDenied {
		return nil
	}

	// Only generate risk if version is too old (< 21) or truly missing
	if bootstrapInfo.HasVersion && bootstrapInfo.Version >= 21 {
		return nil // Version 21+ has the security fixes
	}

	// Create an AWS account target using CloudResource
	accountArn := fmt.Sprintf("arn:aws:iam::%s:root", cdkRole.AccountID)
	awsAccount := &output.CloudResource{
		Platform:     "aws",
		ResourceType: "AWS::IAM::Root",
		ResourceID:   accountArn,
		AccountRef:   cdkRole.AccountID,
		Region:       cdkRole.Region,
		DisplayName:  cdkRole.AccountID,
		Properties: map[string]any{
			"Qualifier":        cdkRole.Qualifier,
			"Region":           cdkRole.Region,
			"BootstrapVersion": bootstrapInfo.Version,
			"HasVersion":       bootstrapInfo.HasVersion,
		},
	}

	var riskName, description, severity string

	if !bootstrapInfo.HasVersion {
		riskName = "cdk-bootstrap-missing"
		description = fmt.Sprintf("AWS CDK bootstrap parameter '/cdk-bootstrap/%s/version' not found in region %s. This indicates CDK was never properly bootstrapped or bootstrap artifacts were deleted.", cdkRole.Qualifier, cdkRole.Region)
		severity = "TM" // TriageMedium
	} else {
		riskName = "cdk-bootstrap-outdated"
		description = fmt.Sprintf("AWS CDK bootstrap version %d is outdated in region %s (< v21). Versions before v21 lack security protections against S3 bucket takeover attacks.", bootstrapInfo.Version, cdkRole.Region)
		severity = "TH" // TriageHigh - Outdated version is high risk
	}

	risk := &output.Risk{
		Target:      awsAccount,
		Name:        riskName,
		DNS:         cdkRole.AccountID,
		Status:      severity,
		Source:      "aurelian-cdk-scanner",
		Description: description,
		Impact:      "CDK deployments may be vulnerable to S3 bucket takeover attacks, potentially allowing attackers to inject malicious CloudFormation templates and gain account access.",
		Recommendation: fmt.Sprintf("Upgrade to CDK v2.149.0+ and re-run 'cdk bootstrap --qualifier %s' in region %s to apply security patches.", cdkRole.Qualifier, cdkRole.Region),
		References:  "https://www.aquasec.com/blog/aws-cdk-risk-exploiting-a-missing-s3-bucket-allowed-account-takeover/\nhttps://docs.aws.amazon.com/cdk/v2/guide/bootstrapping.html",
	}

	if bootstrapInfo.HasVersion {
		risk.Comment = fmt.Sprintf("Bootstrap Version: %d, Qualifier: %s, Region: %s", bootstrapInfo.Version, cdkRole.Qualifier, cdkRole.Region)
	} else {
		risk.Comment = fmt.Sprintf("Bootstrap Version: Missing, Qualifier: %s, Region: %s", cdkRole.Qualifier, cdkRole.Region)
	}

	return risk
}

// isAccessDeniedError checks if the error is due to access denied (permission issue)
func isAccessDeniedError(err error) bool {
	if err == nil {
		return false
	}
	
	errorStr := err.Error()
	return strings.Contains(errorStr, "AccessDenied") || 
		   strings.Contains(errorStr, "access denied") ||
		   strings.Contains(errorStr, "not authorized")
}

// isParameterNotFoundError checks if the error is due to parameter not existing
func isParameterNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	
	// Check for AWS SSM specific parameter not found error
	var paramNotFound *types.ParameterNotFound
	return strings.Contains(err.Error(), "ParameterNotFound") || 
		   strings.Contains(err.Error(), "parameter not found") ||
		   err == paramNotFound // Type assertion for AWS SDK error
}