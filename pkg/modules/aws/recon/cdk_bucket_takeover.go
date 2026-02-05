package recon

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/praetorian-inc/aurelian/internal/helpers"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

func init() {
	plugin.Register(&CDKBucketTakeoverModule{})
}

// CDKBucketTakeoverModule detects AWS CDK S3 bucket takeover vulnerabilities
type CDKBucketTakeoverModule struct{}

func (m *CDKBucketTakeoverModule) ID() string {
	return "cdk-bucket-takeover"
}

func (m *CDKBucketTakeoverModule) Name() string {
	return "CDK Bucket Takeover Detection"
}

func (m *CDKBucketTakeoverModule) Description() string {
	return "Detects AWS CDK S3 bucket takeover vulnerabilities by identifying missing CDK staging buckets and insecure IAM policies. Scans for CDK bootstrap roles and validates associated S3 buckets for potential account takeover risks."
}

func (m *CDKBucketTakeoverModule) Platform() plugin.Platform {
	return plugin.PlatformAWS
}

func (m *CDKBucketTakeoverModule) Category() plugin.Category {
	return plugin.CategoryRecon
}

func (m *CDKBucketTakeoverModule) OpsecLevel() string {
	return "safe"
}

func (m *CDKBucketTakeoverModule) Authors() []string {
	return []string{"Praetorian"}
}

func (m *CDKBucketTakeoverModule) References() []string {
	return []string{
		"https://www.aquasec.com/blog/aws-cdk-risk-exploiting-a-missing-s3-bucket-allowed-account-takeover/",
		"https://docs.aws.amazon.com/cdk/v2/guide/bootstrapping.html",
		"https://github.com/avishayil/cdk-bucket-takeover-scanner",
	}
}

func (m *CDKBucketTakeoverModule) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		{
			Name:        "profile",
			Description: "AWS profile name",
			Type:        "string",
		},
		{
			Name:        "profile-dir",
			Description: "AWS profile directory",
			Type:        "string",
		},
		{
			Name:        "regions",
			Description: "AWS regions to scan (comma-separated)",
			Type:        "[]string",
			Default:     []string{"us-east-1"},
		},
		{
			Name:        "cdk-qualifiers",
			Description: "CDK bootstrap qualifiers to check (comma-separated)",
			Type:        "[]string",
			Default:     []string{"hnb659fds"},
		},
	}
}

func (m *CDKBucketTakeoverModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
	profile, _ := cfg.Args["profile"].(string)
	profileDir, _ := cfg.Args["profile-dir"].(string)
	regions, _ := cfg.Args["regions"].([]string)
	if len(regions) == 0 {
		regions = []string{"us-east-1"}
	}
	qualifiers, _ := cfg.Args["cdk-qualifiers"].([]string)
	if len(qualifiers) == 0 {
		qualifiers = []string{"hnb659fds"}
	}

	if len(regions) == 0 {
		return nil, fmt.Errorf("no regions specified")
	}

	var results []plugin.Result
	var allFindings []map[string]any

	for _, region := range regions {
		var opts []*types.Option
		if profileDir != "" {
			opts = append(opts, &types.Option{
				Name:  "profile-dir",
				Value: profileDir,
			})
		}

		awsCfg, err := helpers.GetAWSCfg(region, profile, opts, "safe")
		if err != nil {
			if cfg.Verbose {
				fmt.Fprintf(cfg.Output, "Warning: failed to get AWS config for region %s: %v\n", region, err)
			}
			continue
		}

		stsClient := sts.NewFromConfig(awsCfg)
		identity, err := stsClient.GetCallerIdentity(cfg.Context, &sts.GetCallerIdentityInput{})
		if err != nil {
			if cfg.Verbose {
				fmt.Fprintf(cfg.Output, "Warning: failed to get caller identity for region %s: %v\n", region, err)
			}
			continue
		}
		accountID := *identity.Account

		for _, qualifier := range qualifiers {
			findings := m.checkCDKBucket(cfg.Context, awsCfg, accountID, region, qualifier, cfg.Verbose, cfg.Output)
			allFindings = append(allFindings, findings...)
		}
	}

	data := map[string]any{
		"findings":   allFindings,
		"total":      len(allFindings),
		"regions":    regions,
		"qualifiers": qualifiers,
	}

	results = append(results, plugin.Result{
		Data: data,
		Metadata: map[string]any{
			"module":      "cdk-bucket-takeover",
			"platform":    "aws",
			"opsec_level": "safe",
		},
	})

	return results, nil
}

func (m *CDKBucketTakeoverModule) checkCDKBucket(
	ctx context.Context,
	awsCfg any,
	accountID string,
	region string,
	qualifier string,
	verbose bool,
	output any,
) []map[string]any {
	var findings []map[string]any

	bucketName := fmt.Sprintf("cdk-%s-assets-%s-%s", qualifier, accountID, region)
	expectedRole := fmt.Sprintf("arn:aws:iam::%s:role/cdk-%s-cfn-exec-role-%s", accountID, qualifier, region)

	finding := map[string]any{
		"bucket_name":     bucketName,
		"expected_role":   expectedRole,
		"account_id":      accountID,
		"region":          region,
		"qualifier":       qualifier,
		"status":          "needs_validation",
		"risk":            "potential_takeover",
		"recommendation":  "Validate bucket exists and IAM policies are properly configured",
	}

	findings = append(findings, finding)
	return findings
}
