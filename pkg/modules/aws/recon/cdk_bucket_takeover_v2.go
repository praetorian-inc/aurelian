package recon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"golang.org/x/sync/errgroup"

	"github.com/praetorian-inc/aurelian/internal/helpers"
	awslink "github.com/praetorian-inc/aurelian/pkg/links/aws"
	"github.com/praetorian-inc/aurelian/pkg/links/options"
	"github.com/praetorian-inc/aurelian/pkg/output"
	aureliantypes "github.com/praetorian-inc/aurelian/pkg/types"
)

// CdkBucketTakeoverV2 detects AWS CDK S3 bucket takeover vulnerabilities
// using V2 three-layer architecture (plain Go patterns, no janus-framework).
type CdkBucketTakeoverV2 struct {
	// Public configuration
	Profile    string
	Regions    []string
	Qualifiers []string // Manual CDK qualifiers to check (default: hnb659fds)

	// Internal state (initialized by Run)
	iamClients map[string]*iam.Client
	ssmClients map[string]*ssm.Client
	s3Clients  map[string]*s3.Client
	stsClient  *sts.Client
	config     aws.Config
	accountID  string
}

// NewCdkBucketTakeoverV2 creates a new V2 CDK bucket takeover detector with sensible defaults.
func NewCdkBucketTakeoverV2(profile string, regions []string) *CdkBucketTakeoverV2 {
	return &CdkBucketTakeoverV2{
		Profile:    profile,
		Regions:    regions,
		Qualifiers: []string{"hnb659fds"}, // Default CDK qualifier
	}
}

// WithQualifiers sets custom CDK qualifiers to check
func (c *CdkBucketTakeoverV2) WithQualifiers(qualifiers []string) *CdkBucketTakeoverV2 {
	c.Qualifiers = qualifiers
	return c
}

// defaultCacheOptions returns the default cache options required by GetAWSCfg.
func (c *CdkBucketTakeoverV2) defaultCacheOptions() []*aureliantypes.Option {
	return []*aureliantypes.Option{
		&options.AwsCacheDirOpt,
		&options.AwsCacheExtOpt,
		&options.AwsCacheTTLOpt,
		&options.AwsDisableCacheOpt,
		&options.AwsCacheErrorRespOpt,
		&options.AwsCacheErrorRespTypesOpt,
	}
}

// Run executes the CDK bucket takeover detection workflow.
// Returns detected risks.
//
// Workflow:
// 1. Initialize AWS clients
// 2. Get account ID
// 3. Discover CDK qualifiers (from SSM or IAM)
// 4. For each region, detect CDK roles (bounded concurrency: 10)
// 5. For each role: check bootstrap, validate bucket, analyze policy (bounded concurrency: 25)
// 6. Collect and return risks
func (c *CdkBucketTakeoverV2) Run(ctx context.Context) ([]output.Risk, error) {
	// 1. Initialize AWS clients
	if err := c.initialize(ctx); err != nil {
		return nil, fmt.Errorf("initialization failed: %w", err)
	}

	// 2. Discover qualifiers (extends c.Qualifiers with discovered ones)
	allQualifiers, err := c.discoverQualifiers(ctx)
	if err != nil {
		slog.Warn("qualifier discovery failed, using configured qualifiers", "error", err)
		allQualifiers = c.Qualifiers
	}

	slog.Info("CDK bucket takeover scan starting", "account_id", c.accountID, "regions", len(c.Regions), "qualifiers", len(allQualifiers))

	// 3. Detect CDK roles across all regions with bounded concurrency
	rolesCh := make(chan awslink.CDKRoleInfo, 100)
	var detectErr error
	var detectWg sync.WaitGroup
	detectWg.Add(1)
	go func() {
		defer detectWg.Done()
		defer close(rolesCh)
		detectErr = c.detectRolesAcrossRegions(ctx, allQualifiers, rolesCh)
	}()

	// 4. Process each role: check bootstrap, validate bucket, analyze policy
	risksCh := make(chan output.Risk, 100)
	procErr := c.processRoles(ctx, rolesCh, risksCh)

	// 5. Close risk channel after processing completes
	close(risksCh)

	// 6. Collect all risks
	var risks []output.Risk
	for risk := range risksCh {
		risks = append(risks, risk)
	}

	// 7. Wait for detection to finish and check errors
	detectWg.Wait()
	if detectErr != nil {
		return risks, fmt.Errorf("role detection failed: %w", detectErr)
	}
	if procErr != nil {
		return risks, fmt.Errorf("role processing failed: %w", procErr)
	}

	slog.Info("CDK bucket takeover scan complete", "risks_found", len(risks))
	return risks, nil
}

// initialize sets up AWS clients for all regions.
func (c *CdkBucketTakeoverV2) initialize(ctx context.Context) error {
	opts := c.defaultCacheOptions()

	// Load base AWS config for us-east-1 (for STS)
	cfg, err := helpers.GetAWSCfg("us-east-1", c.Profile, opts, "moderate")
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}
	c.config = cfg
	c.stsClient = sts.NewFromConfig(cfg)

	// Get account ID
	accountID, err := c.getAccountID(ctx)
	if err != nil {
		return fmt.Errorf("failed to get account ID: %w", err)
	}
	c.accountID = accountID

	// Create clients for each region
	c.iamClients = make(map[string]*iam.Client)
	c.ssmClients = make(map[string]*ssm.Client)
	c.s3Clients = make(map[string]*s3.Client)

	for _, region := range c.Regions {
		regionCfg, err := helpers.GetAWSCfg(region, c.Profile, opts, "moderate")
		if err != nil {
			return fmt.Errorf("failed to load AWS config for region %s: %w", region, err)
		}
		c.iamClients[region] = iam.NewFromConfig(regionCfg)
		c.ssmClients[region] = ssm.NewFromConfig(regionCfg)
		c.s3Clients[region] = s3.NewFromConfig(regionCfg)
	}

	return nil
}

// getAccountID retrieves the current AWS account ID using STS.
func (c *CdkBucketTakeoverV2) getAccountID(ctx context.Context) (string, error) {
	result, err := c.stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", fmt.Errorf("failed to get caller identity: %w", err)
	}
	if result.Account == nil {
		return "", fmt.Errorf("account ID not found in caller identity")
	}
	return *result.Account, nil
}

// discoverQualifiers discovers CDK qualifiers from SSM parameters and IAM roles.
// Returns all discovered qualifiers merged with configured ones.
func (c *CdkBucketTakeoverV2) discoverQualifiers(ctx context.Context) ([]string, error) {
	allQualifiers := make(map[string]bool)

	// Start with configured qualifiers
	for _, q := range c.Qualifiers {
		allQualifiers[q] = true
	}

	// Try SSM-based discovery and IAM-based discovery in each region
	for _, region := range c.Regions {
		// Method 1: Try SSM parameters first (more reliable but requires permissions)
		ssmQualifiers, err := c.discoverQualifiersFromSSM(ctx, region)
		if err != nil {
			slog.Debug("SSM qualifier discovery failed", "region", region, "error", err)
		}
		for _, q := range ssmQualifiers {
			allQualifiers[q] = true
		}

		// Method 2: Fallback to IAM-based discovery
		iamQualifiers, err := c.discoverQualifiersFromIAMRoles(ctx, region)
		if err != nil {
			slog.Debug("IAM qualifier discovery failed", "region", region, "error", err)
		}
		for _, q := range iamQualifiers {
			allQualifiers[q] = true
		}
	}

	result := make([]string, 0, len(allQualifiers))
	for q := range allQualifiers {
		result = append(result, q)
	}
	return result, nil
}

// discoverQualifiersFromSSM discovers qualifiers from SSM parameters under /cdk-bootstrap/
func (c *CdkBucketTakeoverV2) discoverQualifiersFromSSM(ctx context.Context, region string) ([]string, error) {
	ssmClient := c.ssmClients[region]

	slog.Debug("scanning for CDK bootstrap SSM parameters", "region", region)

	// Get all parameters under /cdk-bootstrap/ path
	var qualifiers []string
	var nextToken *string

	for {
		result, err := ssmClient.GetParametersByPath(ctx, &ssm.GetParametersByPathInput{
			Path:       aws.String("/cdk-bootstrap/"),
			Recursive:  aws.Bool(true),
			NextToken:  nextToken,
			MaxResults: aws.Int32(10), // AWS SSM maximum allowed batch size
		})

		if err != nil {
			slog.Debug("error scanning SSM parameters", "region", region, "error", err)
			break // Don't fail completely, just move on
		}

		// Extract qualifiers from parameter names
		for _, param := range result.Parameters {
			if param.Name != nil {
				qualifier := extractQualifierFromParameterName(*param.Name)
				if qualifier != "" && !contains(qualifiers, qualifier) {
					qualifiers = append(qualifiers, qualifier)
					slog.Debug("found CDK qualifier from SSM", "qualifier", qualifier, "parameter", *param.Name)
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
func extractQualifierFromParameterName(parameterName string) string {
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

// discoverQualifiersFromIAMRoles discovers CDK qualifiers by listing IAM roles
// CDK roles follow pattern: cdk-{qualifier}-{role-type}-{account-id}-{region}
func (c *CdkBucketTakeoverV2) discoverQualifiersFromIAMRoles(ctx context.Context, region string) ([]string, error) {
	iamClient := c.iamClients[region]

	slog.Debug("scanning IAM roles for CDK qualifiers", "region", region, "account_id", c.accountID)

	// Compile regex for CDK role patterns
	// Pattern: cdk-{qualifier}-{role-type}-{account-id}-{region}
	cdkRolePattern := regexp.MustCompile(fmt.Sprintf(`^cdk-([a-z0-9]+)-(?:file-publishing-role|cfn-exec-role|image-publishing-role|lookup-role|deploy-role)-%s-%s$`, c.accountID, region))

	var qualifiers []string
	var marker *string

	for {
		listInput := &iam.ListRolesInput{
			MaxItems: aws.Int32(1000), // AWS maximum
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
					if !contains(qualifiers, qualifier) {
						qualifiers = append(qualifiers, qualifier)
						slog.Debug("found CDK qualifier from IAM role", "qualifier", qualifier, "role_name", *role.RoleName)
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

	slog.Info("IAM role-based qualifier discovery complete", "region", region, "qualifiers_found", len(qualifiers))
	return qualifiers, nil
}

// detectRolesAcrossRegions detects CDK roles across all regions with bounded concurrency.
func (c *CdkBucketTakeoverV2) detectRolesAcrossRegions(
	ctx context.Context,
	qualifiers []string,
	rolesCh chan<- awslink.CDKRoleInfo,
) error {
	g, gCtx := errgroup.WithContext(ctx)
	g.SetLimit(10) // Limit concurrent API calls per region

	for _, region := range c.Regions {
		region := region // Capture for goroutine
		g.Go(func() error {
			return c.detectCDKRolesInRegion(gCtx, region, qualifiers, rolesCh)
		})
	}

	return g.Wait()
}

// detectCDKRolesInRegion detects CDK roles in a specific region.
// Sends discovered roles to rolesCh.
func (c *CdkBucketTakeoverV2) detectCDKRolesInRegion(
	ctx context.Context,
	region string,
	qualifiers []string,
	rolesCh chan<- awslink.CDKRoleInfo,
) error {
	iamClient := c.iamClients[region]

	// CDK role patterns to look for - focus on file-publishing-role as most vulnerable
	cdkRoleTypes := map[string]string{
		"file-publishing-role":  "File Publishing Role",
		"cfn-exec-role":         "CloudFormation Execution Role",
		"image-publishing-role": "Image Publishing Role",
		"lookup-role":           "Lookup Role",
		"deploy-role":           "Deploy Role",
	}

	for _, qualifier := range qualifiers {
		for roleType := range cdkRoleTypes {
			roleName := fmt.Sprintf("cdk-%s-%s-%s-%s", qualifier, roleType, c.accountID, region)

			slog.Debug("checking for CDK role", "role_name", roleName, "region", region)

			roleInfo, err := c.getCDKRoleInfo(ctx, iamClient, roleName, qualifier, region, roleType)
			if err != nil {
				slog.Debug("CDK role not found or error", "role_name", roleName, "error", err)
				continue
			}

			if roleInfo != nil {
				slog.Debug("found CDK role", "role_name", roleName, "type", roleType)
				rolesCh <- *roleInfo
			}
		}
	}

	return nil
}

// getCDKRoleInfo retrieves information about a CDK role.
func (c *CdkBucketTakeoverV2) getCDKRoleInfo(
	ctx context.Context,
	iamClient *iam.Client,
	roleName, qualifier, region, roleType string,
) (*awslink.CDKRoleInfo, error) {
	// Try to get the role
	getRoleResult, err := iamClient.GetRole(ctx, &iam.GetRoleInput{
		RoleName: &roleName,
	})
	if err != nil {
		// Role doesn't exist or we don't have permission
		return nil, err
	}

	if getRoleResult.Role == nil {
		return nil, fmt.Errorf("role result is nil")
	}

	role := getRoleResult.Role

	// Extract creation date
	createdDate := ""
	if role.CreateDate != nil {
		createdDate = role.CreateDate.Format("2006-01-02T15:04:05Z")
	}

	// Extract trust policy if available
	trustPolicy := ""
	if role.AssumeRolePolicyDocument != nil {
		trustPolicy = *role.AssumeRolePolicyDocument
	}

	// Generate expected bucket name
	bucketName := fmt.Sprintf("cdk-%s-assets-%s-%s", qualifier, c.accountID, region)

	roleInfo := &awslink.CDKRoleInfo{
		RoleName:      roleName,
		RoleArn:       *role.Arn,
		Qualifier:     qualifier,
		Region:        region,
		AccountID:     c.accountID,
		CreationDate:  createdDate,
		RoleType:      roleType,
		BucketName:    bucketName,
		AssumeRoleDoc: trustPolicy,
	}

	// Try to get inline policies for additional context
	listPoliciesResult, err := iamClient.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{
		RoleName: &roleName,
	})
	if err == nil && listPoliciesResult.PolicyNames != nil && len(listPoliciesResult.PolicyNames) > 0 {
		// Get the first inline policy for additional context
		policyName := listPoliciesResult.PolicyNames[0]
		getPolicyResult, err := iamClient.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
			RoleName:   &roleName,
			PolicyName: &policyName,
		})
		if err == nil && getPolicyResult.PolicyDocument != nil {
			roleInfo.TrustPolicy = *getPolicyResult.PolicyDocument
		}
	}

	return roleInfo, nil
}

// processRoles processes each role: checks bootstrap, validates bucket, analyzes policy.
// Uses bounded concurrency via errgroup.
func (c *CdkBucketTakeoverV2) processRoles(
	ctx context.Context,
	rolesCh <-chan awslink.CDKRoleInfo,
	risksCh chan<- output.Risk,
) error {
	g, gCtx := errgroup.WithContext(ctx)
	g.SetLimit(25) // Match V2 pattern concurrency limit

	for role := range rolesCh {
		role := role // Capture for goroutine

		select {
		case <-gCtx.Done():
			return gCtx.Err()
		default:
		}

		g.Go(func() error {
			return c.processRole(gCtx, role, risksCh)
		})
	}

	return g.Wait()
}

// processRole processes a single CDK role:
// 1. Check bootstrap version -> may generate risk
// 2. Validate bucket existence -> may generate risk
// 3. Analyze policy (for file-publishing-role) -> may generate risk
func (c *CdkBucketTakeoverV2) processRole(
	ctx context.Context,
	role awslink.CDKRoleInfo,
	risksCh chan<- output.Risk,
) error {
	// Step 1: Check bootstrap version
	bootstrapInfo, err := c.checkBootstrapVersion(ctx, role.Region, role.Qualifier)
	if err != nil {
		slog.Debug("failed to check bootstrap version", "error", err)
	} else {
		if risk := c.generateBootstrapVersionRisk(role, bootstrapInfo); risk != nil {
			risksCh <- *risk
		}
	}

	// Step 2: Validate bucket
	bucketExists, bucketOwnedByAccount, err := c.validateBucket(ctx, role)
	if err != nil {
		slog.Debug("failed to validate bucket", "bucket", role.BucketName, "error", err)
	} else {
		if risk := c.generateBucketRisk(role, bucketExists, bucketOwnedByAccount); risk != nil {
			risksCh <- *risk
		}
	}

	// Step 3: Analyze policy (only for file-publishing-role)
	if strings.Contains(role.RoleType, "file-publishing-role") {
		hasRestriction, err := c.analyzePolicy(ctx, role)
		if err != nil {
			slog.Debug("failed to analyze policy", "role", role.RoleName, "error", err)
		} else if !hasRestriction {
			if risk := c.generatePolicyRisk(role); risk != nil {
				risksCh <- *risk
			}
		}
	}

	return nil
}

// checkBootstrapVersion checks CDK bootstrap version from SSM parameter.
func (c *CdkBucketTakeoverV2) checkBootstrapVersion(
	ctx context.Context,
	region, qualifier string,
) (awslink.CDKBootstrapInfo, error) {
	ssmClient := c.ssmClients[region]
	parameterName := fmt.Sprintf("/cdk-bootstrap/%s/version", qualifier)

	slog.Debug("checking bootstrap version parameter", "parameter", parameterName, "region", region)

	result, err := ssmClient.GetParameter(ctx, &ssm.GetParameterInput{
		Name: &parameterName,
	})

	bootstrapInfo := awslink.CDKBootstrapInfo{
		AccountID:    c.accountID,
		Region:       region,
		Qualifier:    qualifier,
		HasVersion:   false,
		AccessDenied: false,
	}

	if err != nil {
		// Check if this is a permission error vs parameter not found
		if isAccessDeniedError(err) {
			slog.Info("SSM parameter access denied - cannot determine bootstrap status", "parameter", parameterName, "error", err)
			bootstrapInfo.AccessDenied = true
		} else if isParameterNotFoundError(err) {
			slog.Debug("CDK bootstrap parameter not found", "parameter", parameterName)
			// HasVersion remains false for truly missing parameters
		} else {
			slog.Debug("failed to get CDK bootstrap version parameter", "parameter", parameterName, "error", err)
		}
		return bootstrapInfo, err
	}

	if result.Parameter != nil && result.Parameter.Value != nil {
		if version, err := strconv.Atoi(*result.Parameter.Value); err == nil {
			bootstrapInfo.Version = version
			bootstrapInfo.HasVersion = true
			slog.Debug("found CDK bootstrap version", "version", version, "qualifier", qualifier, "region", region)
		} else {
			slog.Debug("failed to parse CDK bootstrap version", "value", *result.Parameter.Value, "error", err)
		}
	}

	return bootstrapInfo, nil
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
		errors.As(err, &paramNotFound)
}

// validateBucket checks if CDK staging bucket exists and is owned by correct account.
func (c *CdkBucketTakeoverV2) validateBucket(
	ctx context.Context,
	role awslink.CDKRoleInfo,
) (exists bool, ownedByAccount bool, err error) {
	s3Client := c.s3Clients[role.Region]

	// Try to get bucket location
	_, err = s3Client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{
		Bucket: &role.BucketName,
	})

	if err != nil {
		// Check if it's a NoSuchBucket error
		var noSuchBucket *s3types.NoSuchBucket
		if errors.As(err, &noSuchBucket) {
			slog.Debug("bucket does not exist", "bucket", role.BucketName)
			return false, false, nil
		}

		// Check error message for access denied (simpler approach)
		if strings.Contains(err.Error(), "AccessDenied") || strings.Contains(err.Error(), "access denied") {
			slog.Debug("access denied to bucket - likely owned by different account", "bucket", role.BucketName)
			return true, false, nil
		}

		// Other errors
		slog.Debug("error checking bucket", "bucket", role.BucketName, "error", err)
		return false, false, err
	}

	// Bucket exists and we have access - try to verify ownership
	ownedByAccount, err = c.verifyBucketOwnership(ctx, s3Client, role.BucketName, c.accountID)
	return true, ownedByAccount, err
}

// verifyBucketOwnership verifies if the bucket is owned by the expected account.
func (c *CdkBucketTakeoverV2) verifyBucketOwnership(
	ctx context.Context,
	s3Client *s3.Client,
	bucketName, expectedAccountID string,
) (bool, error) {
	// Try to get bucket policy to see if it references our account
	policyResult, err := s3Client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
		Bucket: &bucketName,
	})

	if err != nil {
		// If policy doesn't exist, we can't verify ownership this way
		if strings.Contains(err.Error(), "NoSuchBucketPolicy") {
			slog.Debug("no bucket policy found", "bucket", bucketName)
			return true, nil // Assume ownership if we can access it and no policy exists
		}
		return false, err
	}

	if policyResult.Policy != nil {
		policyDoc := *policyResult.Policy
		// Simple check - if our account ID appears in the policy, likely owned by us
		if len(policyDoc) > 0 && strings.Contains(policyDoc, expectedAccountID) {
			return true, nil
		}
	}

	// Default to true if we can access the bucket
	return true, nil
}

// analyzePolicy checks if role has proper aws:ResourceAccount restrictions on S3 permissions.
func (c *CdkBucketTakeoverV2) analyzePolicy(
	ctx context.Context,
	role awslink.CDKRoleInfo,
) (hasAccountRestriction bool, err error) {
	iamClient := c.iamClients[role.Region]

	hasAccountRestriction = false

	// Check inline policies
	inlinePolicies, err := iamClient.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{
		RoleName: &role.RoleName,
	})
	if err != nil {
		return false, fmt.Errorf("failed to list inline policies: %w", err)
	}

	for _, policyName := range inlinePolicies.PolicyNames {
		policyDoc, err := iamClient.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
			RoleName:   &role.RoleName,
			PolicyName: &policyName,
		})
		if err != nil {
			slog.Debug("failed to get inline policy", "policy", policyName, "error", err)
			continue
		}

		if policyDoc.PolicyDocument != nil {
			if c.checkPolicyForAccountRestriction(*policyDoc.PolicyDocument, c.accountID) {
				hasAccountRestriction = true
				break
			}
		}
	}

	// If not found in inline policies, check attached managed policies
	if !hasAccountRestriction {
		attachedPolicies, err := iamClient.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
			RoleName: &role.RoleName,
		})
		if err == nil {
			for _, policy := range attachedPolicies.AttachedPolicies {
				if policy.PolicyArn == nil {
					continue
				}

				// Get the policy to find default version
				getPolicyResult, err := iamClient.GetPolicy(ctx, &iam.GetPolicyInput{
					PolicyArn: policy.PolicyArn,
				})
				if err != nil {
					slog.Debug("failed to get managed policy", "arn", *policy.PolicyArn, "error", err)
					continue
				}

				if getPolicyResult.Policy == nil || getPolicyResult.Policy.DefaultVersionId == nil {
					continue
				}

				// Get the default version of the managed policy
				policyVersion, err := iamClient.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
					PolicyArn: policy.PolicyArn,
					VersionId: getPolicyResult.Policy.DefaultVersionId,
				})
				if err != nil {
					slog.Debug("failed to get managed policy version", "arn", *policy.PolicyArn, "error", err)
					continue
				}

				if policyVersion.PolicyVersion != nil && policyVersion.PolicyVersion.Document != nil {
					if c.checkPolicyForAccountRestriction(*policyVersion.PolicyVersion.Document, c.accountID) {
						hasAccountRestriction = true
						break
					}
				}
			}
		}
	}

	return hasAccountRestriction, nil
}

// checkPolicyForAccountRestriction checks if policy has account restrictions.
func (c *CdkBucketTakeoverV2) checkPolicyForAccountRestriction(policyDoc, accountID string) bool {
	// Parse the policy document JSON
	var policy map[string]any
	if err := json.Unmarshal([]byte(policyDoc), &policy); err != nil {
		slog.Debug("failed to parse policy document", "error", err)
		return false
	}

	// Check if policy has Statement array
	statements, ok := policy["Statement"].([]any)
	if !ok {
		return false
	}

	// Look for S3 permissions with account restrictions
	for _, stmt := range statements {
		statement, ok := stmt.(map[string]any)
		if !ok {
			continue
		}

		// Check if this statement affects S3
		if !statementAffectsS3(statement) {
			continue
		}

		// Check for aws:ResourceAccount condition
		if hasResourceAccountCondition(statement, accountID) {
			slog.Debug("found aws:ResourceAccount condition in policy")
			return true
		}

		// Check for explicit account restriction in Resource ARNs
		if hasAccountRestrictedResources(statement, accountID) {
			slog.Debug("found account-restricted resources in policy")
			return true
		}
	}

	return false
}

// statementAffectsS3 checks if a policy statement affects S3.
func statementAffectsS3(statement map[string]any) bool {
	actions, ok := statement["Action"]
	if !ok {
		return false
	}

	// Convert action to string slice for easier checking
	var actionList []string
	switch a := actions.(type) {
	case string:
		actionList = []string{a}
	case []any:
		for _, action := range a {
			if actionStr, ok := action.(string); ok {
				actionList = append(actionList, actionStr)
			}
		}
	default:
		return false
	}

	// Check if any action is S3-related
	for _, action := range actionList {
		if strings.HasPrefix(strings.ToLower(action), "s3:") {
			return true
		}
	}

	return false
}

// hasResourceAccountCondition checks if statement has aws:ResourceAccount condition.
func hasResourceAccountCondition(statement map[string]any, accountID string) bool {
	condition, ok := statement["Condition"].(map[string]any)
	if !ok {
		return false
	}

	// Check for StringEquals or StringLike conditions
	for condType, condValues := range condition {
		if condType != "StringEquals" && condType != "StringLike" {
			continue
		}

		condMap, ok := condValues.(map[string]any)
		if !ok {
			continue
		}

		// Check for aws:ResourceAccount condition
		if resourceAccount, exists := condMap["aws:ResourceAccount"]; exists {
			switch ra := resourceAccount.(type) {
			case string:
				if ra == accountID {
					return true
				}
			case []any:
				for _, val := range ra {
					if valStr, ok := val.(string); ok && valStr == accountID {
						return true
					}
				}
			}
		}
	}

	return false
}

// hasAccountRestrictedResources checks if statement has account-restricted resources.
func hasAccountRestrictedResources(statement map[string]any, accountID string) bool {
	resources, ok := statement["Resource"]
	if !ok {
		return false
	}

	// Convert resource to string slice for easier checking
	var resourceList []string
	switch r := resources.(type) {
	case string:
		resourceList = []string{r}
	case []any:
		for _, resource := range r {
			if resourceStr, ok := resource.(string); ok {
				resourceList = append(resourceList, resourceStr)
			}
		}
	default:
		return false
	}

	// Check if all S3 resources are restricted to our account
	for _, resource := range resourceList {
		if strings.HasPrefix(resource, "arn:aws:s3:::") {
			// If resource contains our account ID or is very specific, it's restricted
			if strings.Contains(resource, accountID) {
				return true
			}
		}
	}

	return false
}

// generateBootstrapVersionRisk creates risk for missing/outdated bootstrap.
func (c *CdkBucketTakeoverV2) generateBootstrapVersionRisk(
	role awslink.CDKRoleInfo,
	bootstrap awslink.CDKBootstrapInfo,
) *output.Risk {
	// Don't generate false positives for permission errors
	if bootstrap.AccessDenied {
		slog.Info("skipping bootstrap risk due to SSM access denied", "qualifier", role.Qualifier, "region", role.Region)
		return nil
	}

	// Only generate risk if version is too old (< 21) or truly missing
	if bootstrap.HasVersion && bootstrap.Version >= 21 {
		return nil // Version 21+ has the security fixes
	}

	// Create an AWS account target using CloudResource
	accountArn := fmt.Sprintf("arn:aws:iam::%s:root", role.AccountID)
	awsAccount := &output.CloudResource{
		Platform:     "aws",
		ResourceType: "AWS::IAM::Root",
		ResourceID:   accountArn,
		AccountRef:   role.AccountID,
		Region:       role.Region,
		DisplayName:  role.AccountID,
		Properties: map[string]any{
			"Qualifier":        role.Qualifier,
			"Region":           role.Region,
			"BootstrapVersion": bootstrap.Version,
			"HasVersion":       bootstrap.HasVersion,
		},
	}

	var riskName, description, severity string

	if !bootstrap.HasVersion {
		riskName = "cdk-bootstrap-missing"
		description = fmt.Sprintf("AWS CDK bootstrap parameter '/cdk-bootstrap/%s/version' not found in region %s. This indicates CDK was never properly bootstrapped or bootstrap artifacts were deleted.", role.Qualifier, role.Region)
		severity = "TM" // TriageMedium
	} else {
		riskName = "cdk-bootstrap-outdated"
		description = fmt.Sprintf("AWS CDK bootstrap version %d is outdated in region %s (< v21). Versions before v21 lack security protections against S3 bucket takeover attacks.", bootstrap.Version, role.Region)
		severity = "TH" // TriageHigh - Outdated version is high risk
	}

	risk := &output.Risk{
		Target:         awsAccount,
		Name:           riskName,
		DNS:            role.AccountID,
		Status:         severity,
		Source:         "nebula-cdk-scanner",
		Description:    description,
		Impact:         "CDK deployments may be vulnerable to S3 bucket takeover attacks, potentially allowing attackers to inject malicious CloudFormation templates and gain account access.",
		Recommendation: fmt.Sprintf("Upgrade to CDK v2.149.0+ and re-run 'cdk bootstrap --qualifier %s' in region %s to apply security patches.", role.Qualifier, role.Region),
		References:     "https://www.aquasec.com/blog/aws-cdk-risk-exploiting-a-missing-s3-bucket-allowed-account-takeover/\nhttps://docs.aws.amazon.com/cdk/v2/guide/bootstrapping.html",
	}

	if bootstrap.HasVersion {
		risk.Comment = fmt.Sprintf("Bootstrap Version: %d, Qualifier: %s, Region: %s", bootstrap.Version, role.Qualifier, role.Region)
	} else {
		risk.Comment = fmt.Sprintf("Bootstrap Version: Missing, Qualifier: %s, Region: %s", role.Qualifier, role.Region)
	}

	return risk
}

// generateBucketRisk creates risk for missing/hijacked bucket.
func (c *CdkBucketTakeoverV2) generateBucketRisk(
	role awslink.CDKRoleInfo,
	bucketExists, bucketOwnedByAccount bool,
) *output.Risk {
	// High risk: CDK roles exist but bucket is missing
	if !bucketExists {
		// Create an AWS account target using CloudResource
		accountArn := fmt.Sprintf("arn:aws:iam::%s:root", role.AccountID)
		awsAccount := &output.CloudResource{
			Platform:     "aws",
			ResourceType: "AWS::IAM::Root",
			ResourceID:   accountArn,
			AccountRef:   role.AccountID,
			Region:       role.Region,
			DisplayName:  role.AccountID,
			Properties: map[string]any{
				"RoleName":   role.RoleName,
				"BucketName": role.BucketName,
				"Qualifier":  role.Qualifier,
				"Region":     role.Region,
			},
		}

		risk := &output.Risk{
			Target:         awsAccount,
			Name:           "cdk-bucket-takeover",
			DNS:            role.AccountID,
			Status:         "TH", // TriageHigh
			Source:         "nebula-cdk-scanner",
			Description:    fmt.Sprintf("AWS CDK staging S3 bucket '%s' is missing but CDK bootstrap role '%s' exists in region %s. This allows potential account takeover through bucket name claiming and CloudFormation template injection.", role.BucketName, role.RoleName, role.Region),
			Impact:         "Attackers can claim the predictable CDK staging bucket name and inject malicious CloudFormation templates, potentially creating admin roles for account takeover.",
			Recommendation: fmt.Sprintf("Re-run 'cdk bootstrap --qualifier %s' in region %s or upgrade to CDK v2.149.0+ and re-bootstrap to apply security patches.", role.Qualifier, role.Region),
			References:     "https://www.aquasec.com/blog/aws-cdk-risk-exploiting-a-missing-s3-bucket-allowed-account-takeover/",
			Comment:        fmt.Sprintf("Role: %s, Expected Bucket: %s, Qualifier: %s, Region: %s", role.RoleName, role.BucketName, role.Qualifier, role.Region),
		}

		return risk
	}

	// Medium risk: Bucket exists but owned by different account
	if bucketExists && !bucketOwnedByAccount {
		// Create an AWS account target using CloudResource
		accountArn := fmt.Sprintf("arn:aws:iam::%s:root", role.AccountID)
		awsAccount := &output.CloudResource{
			Platform:     "aws",
			ResourceType: "AWS::IAM::Root",
			ResourceID:   accountArn,
			AccountRef:   role.AccountID,
			Region:       role.Region,
			DisplayName:  role.AccountID,
			Properties: map[string]any{
				"RoleName":   role.RoleName,
				"BucketName": role.BucketName,
				"Qualifier":  role.Qualifier,
				"Region":     role.Region,
			},
		}

		risk := &output.Risk{
			Target:         awsAccount,
			Name:           "cdk-bucket-hijacked",
			DNS:            role.AccountID,
			Status:         "TM", // TriageMedium
			Source:         "nebula-cdk-scanner",
			Description:    fmt.Sprintf("AWS CDK staging S3 bucket '%s' appears to be owned by a different account, but CDK role '%s' still exists. This indicates a potential bucket takeover.", role.BucketName, role.RoleName),
			Impact:         "CDK deployments may fail or push sensitive CloudFormation templates to an attacker-controlled bucket.",
			Recommendation: fmt.Sprintf("Verify bucket ownership and re-run 'cdk bootstrap --qualifier <new-qualifier>' with a unique qualifier in region %s.", role.Region),
			References:     "https://www.aquasec.com/blog/aws-cdk-risk-exploiting-a-missing-s3-bucket-allowed-account-takeover/",
			Comment:        fmt.Sprintf("Role: %s, Suspicious Bucket: %s, Qualifier: %s, Region: %s", role.RoleName, role.BucketName, role.Qualifier, role.Region),
		}

		return risk
	}

	// No risk found
	return nil
}

// generatePolicyRisk creates risk for unrestricted S3 policy.
func (c *CdkBucketTakeoverV2) generatePolicyRisk(role awslink.CDKRoleInfo) *output.Risk {
	// Create an AWS account target using CloudResource
	accountArn := fmt.Sprintf("arn:aws:iam::%s:root", role.AccountID)
	awsAccount := &output.CloudResource{
		Platform:     "aws",
		ResourceType: "AWS::IAM::Root",
		ResourceID:   accountArn,
		AccountRef:   role.AccountID,
		Region:       role.Region,
		DisplayName:  role.AccountID,
		Properties: map[string]any{
			"RoleName":   role.RoleName,
			"BucketName": role.BucketName,
			"Qualifier":  role.Qualifier,
			"Region":     role.Region,
		},
	}

	description := fmt.Sprintf("AWS CDK FilePublishingRole '%s' lacks proper account restrictions in S3 permissions. This role can potentially access S3 buckets in other accounts, making it vulnerable to bucket takeover attacks.", role.RoleName)
	impact := "The role may inadvertently access attacker-controlled S3 buckets with the same predictable name, allowing CloudFormation template injection."
	recommendation := fmt.Sprintf("Upgrade to CDK v2.149.0+ and re-run 'cdk bootstrap' in region %s, or manually add 'aws:ResourceAccount' condition to the role's S3 permissions.", role.Region)
	references := "https://www.aquasec.com/blog/aws-cdk-risk-exploiting-a-missing-s3-bucket-allowed-account-takeover/"

	comment := fmt.Sprintf("Role: %s, Bucket: %s, Qualifier: %s, Region: %s",
		role.RoleName, role.BucketName, role.Qualifier, role.Region)

	risk := &output.Risk{
		Target:         awsAccount,
		Name:           "cdk-policy-unrestricted",
		DNS:            role.AccountID,
		Status:         "TM", // Triage Medium
		Source:         "nebula-cdk-scanner",
		Description:    description,
		Impact:         impact,
		Recommendation: recommendation,
		References:     references,
		Comment:        comment,
	}

	return risk
}

// contains checks if a string slice contains a specific value
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
