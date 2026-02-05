package aws

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/praetorian-inc/aurelian/pkg/links/aws/base"
)

// CDKQualifierInfo represents discovered CDK qualifier information
type CDKQualifierInfo struct {
	Qualifiers []string `json:"qualifiers"`
	AccountID  string   `json:"account_id"`
	Regions    []string `json:"regions"` // All regions where qualifiers were found
}

type AwsCdkQualifierDiscovery struct {
	*base.NativeAWSLink
}

func NewAwsCdkQualifierDiscovery(args map[string]any) *AwsCdkQualifierDiscovery {
	return &AwsCdkQualifierDiscovery{
		NativeAWSLink: base.NewNativeAWSLink("AwsCdkQualifierDiscovery", args),
	}
}

func (l *AwsCdkQualifierDiscovery) Process(ctx context.Context, input any) ([]any, error) {
	// Get manually specified qualifiers first
	manualQualifiers, _ := l.Arg("cdk-qualifiers").([]string)
	if len(manualQualifiers) == 0 {
		manualQualifiers = []string{"hnb659fds"} // Default CDK qualifier
	}

	// Get current account ID and regions (pass through from role detector if available)
	accountID := ""
	regions := []string{"us-east-1"}
	
	// Check if input contains account/region info from previous links
	if qualInfo, ok := input.(CDKQualifierInfo); ok {
		accountID = qualInfo.AccountID
		regions = qualInfo.Regions
	} else {
		// Get account ID ourselves
		var err error; accountID, err = l.getCurrentAccountID(ctx)
		if err != nil {
			l.Logger().Debug("failed to get current account ID", "error", err)
			return nil, fmt.Errorf("failed to get current account ID: %w", err)
		}

		// Get regions to check - use all standard regions by default for discovery
		configuredRegions, _ := l.Arg("regions").([]string)
		if len(configuredRegions) > 0 && !contains(configuredRegions, "all") {
			regions = configuredRegions
		} else {
			// Default to common CDK regions for discovery
			regions = []string{"us-east-1", "us-west-2", "us-east-2", "eu-west-1"}
		}
	}

	l.Logger().Info("discovering CDK qualifiers", "account_id", accountID, "manual_qualifiers", manualQualifiers)

	// Discover additional qualifiers using multiple methods
	var allQualifiers []string
	allQualifiers = append(allQualifiers, manualQualifiers...)

	for _, region := range regions {
		// Method 1: Try SSM parameters first (more reliable but requires permissions)
		ssmQualifiers, ssmErr := l.discoverQualifiersFromSSM(ctx, region)
		if ssmErr == nil && len(ssmQualifiers) > 0 {
			l.Logger().Info("using SSM-based qualifier discovery", "region", region, "qualifiers_found", len(ssmQualifiers))
			for _, qualifier := range ssmQualifiers {
				if !l.contains(allQualifiers, qualifier) {
					allQualifiers = append(allQualifiers, qualifier)
					l.Logger().Info("discovered CDK qualifier via SSM", "qualifier", qualifier, "region", region)
				}
			}
		} else {
			l.Logger().Debug("SSM qualifier discovery failed, trying IAM fallback", "region", region, "error", ssmErr)
			
			// Method 2: Fallback to IAM role enumeration (more widely accessible)
			iamQualifiers, iamErr := l.discoverQualifiersFromIAMRoles(ctx, region, accountID)
			if iamErr == nil && len(iamQualifiers) > 0 {
				l.Logger().Info("using IAM role-based qualifier discovery", "region", region, "qualifiers_found", len(iamQualifiers))
				for _, qualifier := range iamQualifiers {
					if !l.contains(allQualifiers, qualifier) {
						allQualifiers = append(allQualifiers, qualifier)
						l.Logger().Info("discovered CDK qualifier via IAM roles", "qualifier", qualifier, "region", region)
					}
				}
			} else {
				l.Logger().Debug("both SSM and IAM qualifier discovery failed", "region", region, "ssm_error", ssmErr, "iam_error", iamErr)
			}
		}
	}

	// Create comprehensive qualifier info and send it forward
	qualifierInfo := CDKQualifierInfo{
		Qualifiers: allQualifiers,
		AccountID:  accountID,
		Regions:    regions, // All regions scanned
	}

	l.Logger().Info("CDK qualifier discovery complete", "total_qualifiers", len(allQualifiers), "qualifiers", allQualifiers)
	l.Send(qualifierInfo); return l.Outputs(), nil
}

func (l *AwsCdkQualifierDiscovery) getCurrentAccountID(ctx context.Context) (string, error) {
	awsConfig, err := l.GetConfig(ctx, "us-east-1")
	if err != nil {
		return "", fmt.Errorf("failed to get AWS config: %w", err)
	}

	return getCurrentAccountIDHelper(ctx, awsConfig)
}

// getCurrentAccountIDHelper is a shared helper function for getting AWS account ID
func getCurrentAccountIDHelper(ctx context.Context, awsConfig aws.Config) (string, error) {
	client := sts.NewFromConfig(awsConfig)
	result, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", fmt.Errorf("failed to get caller identity: %w", err)
	}

	if result.Account == nil {
		return "", fmt.Errorf("account ID not found in caller identity")
	}

	return *result.Account, nil
}

func (l *AwsCdkQualifierDiscovery) discoverQualifiersFromSSM(ctx context.Context, region string) ([]string, error) {
	awsConfig, err := l.GetConfig(ctx, region)
	if err != nil {
		return nil, fmt.Errorf("failed to get AWS config for region %s: %w", region, err)
	}

	ssmClient := ssm.NewFromConfig(awsConfig)
	
	l.Logger().Debug("scanning for CDK bootstrap SSM parameters", "region", region)

	// Get all parameters under /cdk-bootstrap/ path
	var qualifiers []string
	var nextToken *string

	for {
		result, err := ssmClient.GetParametersByPath(ctx, &ssm.GetParametersByPathInput{
			Path:           awsStringPtr("/cdk-bootstrap/"),
			Recursive:      awsBoolPtr(true),
			NextToken:      nextToken,
			MaxResults:     awsInt32Ptr(10), // AWS SSM maximum allowed batch size
		})
		
		if err != nil {
			l.Logger().Debug("error scanning SSM parameters", "region", region, "error", err)
			break // Don't fail completely, just move on
		}

		// Extract qualifiers from parameter names
		for _, param := range result.Parameters {
			if param.Name != nil {
				qualifier := l.extractQualifierFromParameterName(*param.Name)
				if qualifier != "" && !l.contains(qualifiers, qualifier) {
					qualifiers = append(qualifiers, qualifier)
					l.Logger().Debug("found CDK qualifier from SSM", "qualifier", qualifier, "parameter", *param.Name)
				}
			}
		}

		// Check if there are more results
		nextToken = result.NextToken
		if nextToken == nil {
			break
		}
	}

	return qualifiers, nil
}

// discoverQualifiersFromIAMRoles discovers CDK qualifiers by listing IAM roles and extracting qualifiers from role names
// This is a fallback method when SSM permissions are not available
// CDK roles follow pattern: cdk-{qualifier}-{role-type}-{account-id}-{region}
func (l *AwsCdkQualifierDiscovery) discoverQualifiersFromIAMRoles(ctx context.Context, region, accountID string) ([]string, error) {
	awsConfig, err := l.GetConfig(ctx, region)
	if err != nil {
		return nil, fmt.Errorf("failed to get AWS config for region %s: %w", region, err)
	}

	iamClient := iam.NewFromConfig(awsConfig)
	
	l.Logger().Debug("scanning IAM roles for CDK qualifiers", "region", region, "account_id", accountID)

	// Compile regex for CDK role patterns
	// Pattern: cdk-{qualifier}-{role-type}-{account-id}-{region}
	cdkRolePattern := regexp.MustCompile(fmt.Sprintf(`^cdk-([a-z0-9]+)-(?:file-publishing-role|cfn-exec-role|image-publishing-role|lookup-role|deploy-role)-%s-%s$`, accountID, region))
	
	var qualifiers []string
	var marker *string

	for {
		listInput := &iam.ListRolesInput{
			MaxItems: awsInt32Ptr(1000), // AWS maximum
			Marker:   marker,
		}

		result, err := iamClient.ListRoles(ctx, listInput)
		if err != nil {
			return nil, fmt.Errorf("failed to list IAM roles in region %s: %w", region, err)
		}

		// Extract qualifiers from CDK role names
		for _, role := range result.Roles {
			if role.RoleName != nil {
				matches := cdkRolePattern.FindStringSubmatch(*role.RoleName)
				if len(matches) == 2 { // Full match + qualifier capture group
					qualifier := matches[1]
					if !l.contains(qualifiers, qualifier) {
						qualifiers = append(qualifiers, qualifier)
						l.Logger().Debug("found CDK qualifier from IAM role", "qualifier", qualifier, "role_name", *role.RoleName)
					}
				}
			}
		}

		// Check if there are more results
		if result.IsTruncated {
			marker = result.Marker
		} else {
			break
		}
	}

	l.Logger().Info("IAM role-based qualifier discovery complete", "region", region, "qualifiers_found", len(qualifiers))
	return qualifiers, nil
}

// extractQualifierFromParameterName extracts qualifier from parameter names like:
// /cdk-bootstrap/myqualifier/version -> "myqualifier"
// /cdk-bootstrap/hnb659fds/version -> "hnb659fds"
func (l *AwsCdkQualifierDiscovery) extractQualifierFromParameterName(parameterName string) string {
	// Expected format: /cdk-bootstrap/{qualifier}/version or similar
	if !strings.HasPrefix(parameterName, "/cdk-bootstrap/") {
		return ""
	}

	// Remove prefix and split by '/'
	withoutPrefix := strings.TrimPrefix(parameterName, "/cdk-bootstrap/")
	parts := strings.Split(withoutPrefix, "/")
	
	if len(parts) >= 1 && parts[0] != "" {
		return parts[0]
	}

	return ""
}

// contains checks if a string slice contains a specific value
func (l *AwsCdkQualifierDiscovery) contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// contains is also a standalone helper for use outside the struct
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// Helper functions for AWS SDK pointers
func awsStringPtr(s string) *string {
	return &s
}

func awsBoolPtr(b bool) *bool {
	return &b
}

func awsInt32Ptr(i int32) *int32 {
	return &i
}