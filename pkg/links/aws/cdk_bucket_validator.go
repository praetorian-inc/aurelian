package aws

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

type AwsCdkBucketValidator struct {
	*base.AwsReconBaseLink
}

func NewAwsCdkBucketValidator(configs ...cfg.Config) chain.Link {
	link := &AwsCdkBucketValidator{}
	link.AwsReconBaseLink = base.NewAwsReconBaseLink(link, configs...)
	link.Base.SetName("AWS CDK Bucket Validator")
	return link
}

func (l *AwsCdkBucketValidator) Params() []cfg.Param {
	return l.AwsReconBaseLink.Params()
}

func (l *AwsCdkBucketValidator) Process(input any) error {
	// Try to extract CDKRoleInfo from input
	cdkRole, ok := input.(CDKRoleInfo)
	if !ok {
		// Pass through non-CDKRoleInfo objects (like Risk objects from other links)
		l.Logger.Debug("input is not CDKRoleInfo, passing through")
		return l.Send(input)
	}

	l.Logger.Info("validating CDK bucket", "role", cdkRole.RoleName, "bucket", cdkRole.BucketName)

	awsConfig, err := l.GetConfigWithRuntimeArgs(cdkRole.Region)
	if err != nil {
		l.Logger.Debug("failed to get AWS config", "region", cdkRole.Region, "error", err)
		return nil // Don't fail the entire chain
	}

	s3Client := s3.NewFromConfig(awsConfig)

	// Check if bucket exists
	bucketExists, bucketOwnedByAccount, err := l.checkBucketExistence(s3Client, cdkRole.BucketName, cdkRole.AccountID)
	if err != nil {
		l.Logger.Debug("error checking bucket existence", "bucket", cdkRole.BucketName, "error", err)
	}

	// Generate risk based on findings
	risk := l.generateCDKBucketRisk(cdkRole, bucketExists, bucketOwnedByAccount)
	if risk != nil {
		l.Logger.Info("found CDK bucket vulnerability", "bucket", cdkRole.BucketName, "risk", risk.Name, "status", risk.Status)
		return l.Send(*risk)
	}

	// If no risk, send the role info for the policy analyzer
	return l.Send(cdkRole)
}

func (l *AwsCdkBucketValidator) checkBucketExistence(s3Client *s3.Client, bucketName, expectedAccountID string) (exists bool, ownedByAccount bool, err error) {
	// Try to get bucket location
	_, err = s3Client.GetBucketLocation(l.Context(), &s3.GetBucketLocationInput{
		Bucket: &bucketName,
	})

	if err != nil {
		// Check if it's a NoSuchBucket error
		var noSuchBucket *s3types.NoSuchBucket
		if errors.As(err, &noSuchBucket) {
			l.Logger.Debug("bucket does not exist", "bucket", bucketName)
			return false, false, nil
		}

		// Check error message for access denied (simpler approach)
		if strings.Contains(err.Error(), "AccessDenied") || strings.Contains(err.Error(), "access denied") {
			l.Logger.Debug("access denied to bucket - likely owned by different account", "bucket", bucketName)
			return true, false, nil
		}

		// Other errors
		l.Logger.Debug("error checking bucket", "bucket", bucketName, "error", err)
		return false, false, err
	}

	// Bucket exists and we have access - try to verify ownership
	ownedByAccount, err = l.verifyBucketOwnership(s3Client, bucketName, expectedAccountID)
	return true, ownedByAccount, err
}

func (l *AwsCdkBucketValidator) verifyBucketOwnership(s3Client *s3.Client, bucketName, expectedAccountID string) (bool, error) {
	// Try to get bucket policy to see if it references our account
	policyResult, err := s3Client.GetBucketPolicy(l.Context(), &s3.GetBucketPolicyInput{
		Bucket: &bucketName,
	})

	if err != nil {
		// If policy doesn't exist, we can't verify ownership this way
		if strings.Contains(err.Error(), "NoSuchBucketPolicy") {
			l.Logger.Debug("no bucket policy found", "bucket", bucketName)
			return true, nil // Assume ownership if we can access it and no policy exists
		}
		return false, err
	}

	if policyResult.Policy != nil {
		policyDoc := *policyResult.Policy
		// Simple check - if our account ID appears in the policy, likely owned by us
		if len(policyDoc) > 0 && containsAccountID(policyDoc, expectedAccountID) {
			return true, nil
		}
	}

	// Default to true if we can access the bucket
	return true, nil
}

func containsAccountID(policyDoc, accountID string) bool {
	// Simple string search - in a real implementation, you'd parse the JSON policy
	return len(accountID) > 0 && len(policyDoc) > 0 && strings.Contains(policyDoc, accountID)
}

func (l *AwsCdkBucketValidator) generateCDKBucketRisk(cdkRole CDKRoleInfo, bucketExists, bucketOwnedByAccount bool) *model.Risk {

	// High risk: CDK roles exist but bucket is missing
	if !bucketExists {
		// Create an AWS account target using AWSResource
		accountArn := fmt.Sprintf("arn:aws:iam::%s:root", cdkRole.AccountID)
		awsAccount, err := model.NewAWSResource(accountArn, cdkRole.AccountID, model.CloudResourceType("AWS::IAM::Root"), map[string]any{
			"RoleName":   cdkRole.RoleName,
			"BucketName": cdkRole.BucketName,
			"Qualifier":  cdkRole.Qualifier,
			"Region":     cdkRole.Region,
		})
		if err != nil {
			l.Logger.Debug("failed to create AWS resource target", "error", err)
			return nil
		}

		risk := model.NewRiskWithDNS(
			&awsAccount,
			"cdk-bucket-takeover",
			cdkRole.AccountID,
			model.TriageHigh,
		)
		risk.Source = "nebula-cdk-scanner"

		// Create risk definition with detailed info
		riskDef := model.RiskDefinition{
			Description:    fmt.Sprintf("AWS CDK staging S3 bucket '%s' is missing but CDK bootstrap role '%s' exists in region %s. This allows potential account takeover through bucket name claiming and CloudFormation template injection.", cdkRole.BucketName, cdkRole.RoleName, cdkRole.Region),
			Impact:         "Attackers can claim the predictable CDK staging bucket name and inject malicious CloudFormation templates, potentially creating admin roles for account takeover.",
			Recommendation: fmt.Sprintf("Re-run 'cdk bootstrap --qualifier %s' in region %s or upgrade to CDK v2.149.0+ and re-bootstrap to apply security patches.", cdkRole.Qualifier, cdkRole.Region),
			References:     "https://www.aquasec.com/blog/aws-cdk-risk-exploiting-a-missing-s3-bucket-allowed-account-takeover/",
		}

		// Store additional context in risk attributes
		risk.Comment = fmt.Sprintf("Role: %s, Expected Bucket: %s, Qualifier: %s, Region: %s",
			cdkRole.RoleName, cdkRole.BucketName, cdkRole.Qualifier, cdkRole.Region)

		// Generate risk definition file
		risk.Definition(riskDef)

		// Store instance-specific proof with description, impact, remediation, and references
		proofContent := fmt.Sprintf(`#### Vulnerability Description
AWS CDK staging S3 bucket '%s' is missing but CDK bootstrap role '%s' exists in region %s. This allows potential account takeover through bucket name claiming and CloudFormation template injection.

#### Impact
Attackers can claim the predictable CDK staging bucket name and inject malicious CloudFormation templates, potentially creating admin roles for account takeover.

#### Remediation
Re-run 'cdk bootstrap --qualifier %s' in region %s or upgrade to CDK v2.149.0+ and re-bootstrap to apply security patches.

#### References
https://www.aquasec.com/blog/aws-cdk-risk-exploiting-a-missing-s3-bucket-allowed-account-takeover/

#### Evidence
- Role Name: %s
- Expected Bucket: %s
- Qualifier: %s
- Region: %s
- Account ID: %s
`,
			cdkRole.BucketName, cdkRole.RoleName, cdkRole.Region,
			cdkRole.Qualifier, cdkRole.Region,
			cdkRole.RoleName, cdkRole.BucketName, cdkRole.Qualifier, cdkRole.Region, cdkRole.AccountID)
		// Create proof file with unique name including qualifier and region
		proofFile := model.NewFile(fmt.Sprintf("proofs/%s/%s-%s-%s", cdkRole.AccountID, risk.Name, cdkRole.Qualifier, cdkRole.Region))
		proofFile.Bytes = []byte(proofContent)
		if err := l.Send(proofFile); err != nil {
			l.Logger.Debug("failed to send proof file", "error", err, "bucket", cdkRole.BucketName)
		}

		return &risk
	}

	// Medium risk: Bucket exists but owned by different account
	if bucketExists && !bucketOwnedByAccount {
		// Create an AWS account target using AWSResource
		accountArn := fmt.Sprintf("arn:aws:iam::%s:root", cdkRole.AccountID)
		awsAccount, err := model.NewAWSResource(accountArn, cdkRole.AccountID, model.CloudResourceType("AWS::IAM::Root"), map[string]any{
			"RoleName":   cdkRole.RoleName,
			"BucketName": cdkRole.BucketName,
			"Qualifier":  cdkRole.Qualifier,
			"Region":     cdkRole.Region,
		})
		if err != nil {
			l.Logger.Debug("failed to create AWS resource target", "error", err)
			return nil
		}

		risk := model.NewRiskWithDNS(
			&awsAccount,
			"cdk-bucket-hijacked",
			cdkRole.AccountID,
			model.TriageMedium,
		)
		risk.Source = "nebula-cdk-scanner"

		riskDef := model.RiskDefinition{
			Description:    fmt.Sprintf("AWS CDK staging S3 bucket '%s' appears to be owned by a different account, but CDK role '%s' still exists. This indicates a potential bucket takeover.", cdkRole.BucketName, cdkRole.RoleName),
			Impact:         "CDK deployments may fail or push sensitive CloudFormation templates to an attacker-controlled bucket.",
			Recommendation: fmt.Sprintf("Verify bucket ownership and re-run 'cdk bootstrap --qualifier <new-qualifier>' with a unique qualifier in region %s.", cdkRole.Region),
			References:     "https://www.aquasec.com/blog/aws-cdk-risk-exploiting-a-missing-s3-bucket-allowed-account-takeover/",
		}

		risk.Comment = fmt.Sprintf("Role: %s, Suspicious Bucket: %s, Qualifier: %s, Region: %s",
			cdkRole.RoleName, cdkRole.BucketName, cdkRole.Qualifier, cdkRole.Region)

		risk.Definition(riskDef)

		// Store instance-specific proof with description, impact, remediation, and references
		proofContent := fmt.Sprintf(`#### Vulnerability Description
AWS CDK staging S3 bucket '%s' appears to be owned by a different account, but CDK role '%s' still exists in region %s. This indicates a potential bucket takeover.

#### Impact
CDK deployments may fail or push sensitive CloudFormation templates to an attacker-controlled bucket.

#### Remediation
Verify bucket ownership and re-run 'cdk bootstrap --qualifier <new-qualifier>' with a unique qualifier in region %s.

#### References
https://www.aquasec.com/blog/aws-cdk-risk-exploiting-a-missing-s3-bucket-allowed-account-takeover/

#### Evidence
- Role Name: %s
- Suspicious Bucket: %s
- Qualifier: %s
- Region: %s
- Account ID: %s
`,
			cdkRole.BucketName, cdkRole.RoleName, cdkRole.Region,
			cdkRole.Region,
			cdkRole.RoleName, cdkRole.BucketName, cdkRole.Qualifier, cdkRole.Region, cdkRole.AccountID)
		// Create proof file with unique name including qualifier and region
		proofFile := model.NewFile(fmt.Sprintf("proofs/%s/%s-%s-%s", cdkRole.AccountID, risk.Name, cdkRole.Qualifier, cdkRole.Region))
		proofFile.Bytes = []byte(proofContent)
		if err := l.Send(proofFile); err != nil {
			l.Logger.Debug("failed to send proof file", "error", err, "bucket", cdkRole.BucketName)
		}

		return &risk
	}

	// No risk found
	return nil
}
