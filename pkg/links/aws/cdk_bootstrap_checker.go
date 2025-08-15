package aws

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/tabularium/pkg/model/model"
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
	*base.AwsReconBaseLink
}

func NewAwsCdkBootstrapChecker(configs ...cfg.Config) chain.Link {
	link := &AwsCdkBootstrapChecker{}
	link.AwsReconBaseLink = base.NewAwsReconBaseLink(link, configs...)
	link.Base.SetName("AWS CDK Bootstrap Version Checker")
	return link
}

func (l *AwsCdkBootstrapChecker) Params() []cfg.Param {
	return l.AwsReconBaseLink.Params()
}

func (l *AwsCdkBootstrapChecker) Process(input any) error {
	// Try to extract CDKRoleInfo from input
	cdkRole, ok := input.(CDKRoleInfo)
	if !ok {
		l.Logger.Debug("input is not CDKRoleInfo, skipping")
		return nil
	}

	l.Logger.Info("checking CDK bootstrap version", "qualifier", cdkRole.Qualifier, "region", cdkRole.Region)

	awsConfig, err := l.GetConfigWithRuntimeArgs(cdkRole.Region)
	if err != nil {
		l.Logger.Debug("failed to get AWS config", "region", cdkRole.Region, "error", err)
		return l.Send(cdkRole) // Pass through even if we can't check version
	}

	ssmClient := ssm.NewFromConfig(awsConfig)

	// Check CDK bootstrap version from SSM parameter
	bootstrapInfo := l.checkBootstrapVersion(ssmClient, cdkRole.AccountID, cdkRole.Region, cdkRole.Qualifier)
	
	// Generate risk if version is too old or missing
	if risk := l.generateBootstrapVersionRisk(cdkRole, bootstrapInfo); risk != nil {
		l.Logger.Info("found CDK bootstrap version vulnerability", "version", bootstrapInfo.Version, "risk", risk.Name)
		if err := l.Send(*risk); err != nil {
			l.Logger.Debug("failed to send bootstrap version risk", "error", err)
		}
	}

	// Pass through the original role info for other links
	return l.Send(cdkRole)
}

func (l *AwsCdkBootstrapChecker) checkBootstrapVersion(ssmClient *ssm.Client, accountID, region, qualifier string) CDKBootstrapInfo {
	parameterName := fmt.Sprintf("/cdk-bootstrap/%s/version", qualifier)
	
	l.Logger.Debug("checking bootstrap version parameter", "parameter", parameterName, "region", region)
	
	result, err := ssmClient.GetParameter(l.Context(), &ssm.GetParameterInput{
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
			l.Logger.Info("SSM parameter access denied - cannot determine bootstrap status", "parameter", parameterName, "error", err)
			bootstrapInfo.AccessDenied = true
		} else if isParameterNotFoundError(err) {
			l.Logger.Debug("CDK bootstrap parameter not found", "parameter", parameterName)
			// HasVersion remains false for truly missing parameters
		} else {
			l.Logger.Debug("failed to get CDK bootstrap version parameter", "parameter", parameterName, "error", err)
		}
		return bootstrapInfo
	}
	
	if result.Parameter != nil && result.Parameter.Value != nil {
		if version, err := strconv.Atoi(*result.Parameter.Value); err == nil {
			bootstrapInfo.Version = version
			bootstrapInfo.HasVersion = true
			l.Logger.Debug("found CDK bootstrap version", "version", version, "qualifier", qualifier, "region", region)
		} else {
			l.Logger.Debug("failed to parse CDK bootstrap version", "value", *result.Parameter.Value, "error", err)
		}
	}
	
	return bootstrapInfo
}

func (l *AwsCdkBootstrapChecker) generateBootstrapVersionRisk(cdkRole CDKRoleInfo, bootstrapInfo CDKBootstrapInfo) *model.Risk {
	// Don't generate false positives for permission errors
	if bootstrapInfo.AccessDenied {
		l.Logger.Info("skipping bootstrap risk due to SSM access denied", "qualifier", cdkRole.Qualifier, "region", cdkRole.Region)
		return nil
	}
	
	// Only generate risk if version is too old (< 21) or truly missing
	if bootstrapInfo.HasVersion && bootstrapInfo.Version >= 21 {
		return nil // Version 21+ has the security fixes
	}
	
	// Create an AWS account target using AWSResource
	accountArn := fmt.Sprintf("arn:aws:iam::%s:root", cdkRole.AccountID)
	awsAccount, err := model.NewAWSResource(accountArn, cdkRole.AccountID, model.CloudResourceType("AWS::IAM::Root"), map[string]any{
		"Qualifier": cdkRole.Qualifier,
		"Region": cdkRole.Region,
		"BootstrapVersion": bootstrapInfo.Version,
		"HasVersion": bootstrapInfo.HasVersion,
	})
	if err != nil {
		l.Logger.Debug("failed to create AWS resource target", "error", err)
		return nil
	}
	
	var riskName, description, severity string
	
	if !bootstrapInfo.HasVersion {
		riskName = "cdk-bootstrap-missing"
		description = fmt.Sprintf("AWS CDK bootstrap parameter '/cdk-bootstrap/%s/version' not found in region %s. This indicates CDK was never properly bootstrapped or bootstrap artifacts were deleted.", cdkRole.Qualifier, cdkRole.Region)
		severity = model.TriageMedium
	} else {
		riskName = "cdk-bootstrap-outdated"
		description = fmt.Sprintf("AWS CDK bootstrap version %d is outdated in region %s (< v21). Versions before v21 lack security protections against S3 bucket takeover attacks.", bootstrapInfo.Version, cdkRole.Region)
		severity = model.TriageHigh // Outdated version is high risk
	}
	
	risk := model.NewRiskWithDNS(
		&awsAccount,
		riskName,
		cdkRole.AccountID,
		severity,
	)
	risk.Source = "nebula-cdk-scanner"
	
	riskDef := model.RiskDefinition{
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
	
	risk.Definition(riskDef)
	
	return &risk
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