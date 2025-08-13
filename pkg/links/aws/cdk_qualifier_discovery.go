package aws

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/links/options"
)

// CDKQualifierInfo represents discovered CDK qualifier information
type CDKQualifierInfo struct {
	Qualifiers []string `json:"qualifiers"`
	AccountID  string   `json:"account_id"`
	Regions    []string `json:"regions"` // All regions where qualifiers were found
}

type AwsCdkQualifierDiscovery struct {
	*base.AwsReconBaseLink
}

func NewAwsCdkQualifierDiscovery(configs ...cfg.Config) chain.Link {
	link := &AwsCdkQualifierDiscovery{}
	link.AwsReconBaseLink = base.NewAwsReconBaseLink(link, configs...)
	link.Base.SetName("AWS CDK Qualifier Discovery")
	return link
}

func (l *AwsCdkQualifierDiscovery) Params() []cfg.Param {
	return append(l.AwsReconBaseLink.Params(), 
		options.AwsCdkQualifiers(),
	)
}

func (l *AwsCdkQualifierDiscovery) Process(input any) error {
	// Get manually specified qualifiers first
	manualQualifiers, err := cfg.As[[]string](l.Arg("cdk-qualifiers"))
	if err != nil || len(manualQualifiers) == 0 {
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
		accountID, err = l.getCurrentAccountID()
		if err != nil {
			l.Logger.Debug("failed to get current account ID", "error", err)
			return fmt.Errorf("failed to get current account ID: %w", err)
		}

		// Get regions to check - use all standard regions by default for discovery
		configuredRegions, err := cfg.As[[]string](l.Arg("regions"))
		if err == nil && len(configuredRegions) > 0 && !contains(configuredRegions, "all") {
			regions = configuredRegions
		} else {
			// Default to common CDK regions for discovery
			regions = []string{"us-east-1", "us-west-2", "us-east-2", "eu-west-1"}
		}
	}

	l.Logger.Info("discovering CDK qualifiers", "account_id", accountID, "manual_qualifiers", manualQualifiers)

	// Discover additional qualifiers from SSM parameters
	var allQualifiers []string
	allQualifiers = append(allQualifiers, manualQualifiers...)

	for _, region := range regions {
		discoveredQualifiers, err := l.discoverQualifiersInRegion(region)
		if err != nil {
			l.Logger.Debug("failed to discover qualifiers in region", "region", region, "error", err)
			continue
		}

		// Add newly discovered qualifiers
		for _, qualifier := range discoveredQualifiers {
			if !l.contains(allQualifiers, qualifier) {
				allQualifiers = append(allQualifiers, qualifier)
				l.Logger.Info("discovered CDK qualifier", "qualifier", qualifier, "region", region)
			}
		}
	}

	// Create comprehensive qualifier info and send it forward
	qualifierInfo := CDKQualifierInfo{
		Qualifiers: allQualifiers,
		AccountID:  accountID,
		Regions:    regions, // All regions scanned
	}

	l.Logger.Info("CDK qualifier discovery complete", "total_qualifiers", len(allQualifiers), "qualifiers", allQualifiers)
	return l.Send(qualifierInfo)
}

func (l *AwsCdkQualifierDiscovery) getCurrentAccountID() (string, error) {
	awsConfig, err := l.GetConfigWithRuntimeArgs("us-east-1")
	if err != nil {
		return "", fmt.Errorf("failed to get AWS config: %w", err)
	}

	return getCurrentAccountIDHelper(l.Context(), awsConfig)
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

func (l *AwsCdkQualifierDiscovery) discoverQualifiersInRegion(region string) ([]string, error) {
	awsConfig, err := l.GetConfigWithRuntimeArgs(region)
	if err != nil {
		return nil, fmt.Errorf("failed to get AWS config for region %s: %w", region, err)
	}

	ssmClient := ssm.NewFromConfig(awsConfig)
	
	l.Logger.Debug("scanning for CDK bootstrap SSM parameters", "region", region)

	// Get all parameters under /cdk-bootstrap/ path
	var qualifiers []string
	var nextToken *string

	for {
		result, err := ssmClient.GetParametersByPath(l.Context(), &ssm.GetParametersByPathInput{
			Path:           awsStringPtr("/cdk-bootstrap/"),
			Recursive:      awsBoolPtr(true),
			NextToken:      nextToken,
			MaxResults:     awsInt32Ptr(10), // AWS SSM maximum allowed batch size
		})
		
		if err != nil {
			l.Logger.Debug("error scanning SSM parameters", "region", region, "error", err)
			break // Don't fail completely, just move on
		}

		// Extract qualifiers from parameter names
		for _, param := range result.Parameters {
			if param.Name != nil {
				qualifier := l.extractQualifierFromParameterName(*param.Name)
				if qualifier != "" && !l.contains(qualifiers, qualifier) {
					qualifiers = append(qualifiers, qualifier)
					l.Logger.Debug("found CDK qualifier from SSM", "qualifier", qualifier, "parameter", *param.Name)
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