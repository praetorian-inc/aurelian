package options

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

var AwsAccessKeyIdOpt = types.Option{
	Name:        "access-key-id",
	Short:       "k",
	Description: "AWS access key ID",
	Required:    true,
	Type:        types.String,
	Value:       "",
	ValueFormat: regexp.MustCompile("([^A-Z0-9]|^)(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{12,}"),
}

var AwsAccountIdOpt = types.Option{
	Name:        "account-id",
	Short:       "i",
	Description: "AWS account ID",
	Required:    true,
	Type:        types.String,
	Value:       "",
	ValueFormat: regexp.MustCompile("[0-9]{12}"),
}

var AwsRegionOpt = types.Option{
	Name:        "region",
	Short:       "r",
	Description: "AWS region",
	Required:    true,
	Type:        types.String,
	Value:       "us-east-1",
}

var AwsRegionsOpt = types.Option{
	Name:        "regions",
	Short:       "r",
	Description: "Comma separated list of AWS regions. Can be 'all' for all regions.",
	Required:    true,
	Type:        types.String,
	Value:       "",
}

var AwsResourceTypeOpt = types.Option{
	Name:        "resource-type",
	Short:       "t",
	Description: "AWS Cloud Control resource type",
	Required:    true,
	Type:        types.String,
	Value:       "",
	ValueFormat: regexp.MustCompile("^(AWS::[a-zA-Z0-9:]+|ALL|all)$"),
}

var FindSecretsTypes = []string{
	"AWS::CloudFormation::Stack",
	"AWS::Lambda::Function",
	"AWS::Lambda::Function::Code",
	"AWS::EC2::Instance",
	"AWS::ECR::Repository",
	"AWS::ECR::PublicRepository",
	"AWS::ECS::TaskDefinition",
	"AWS::SSM::Parameter",
	"AWS::SSM::Document",
	"AWS::StepFunctions::StateMachine",
	"AWS::Logs::LogGroup",
	"AWS::Logs::LogStream",
	"AWS::Logs::MetricFilter",
	"AWS::Logs::SubscriptionFilter",
	"ALL",
}

var AwsFindSecretsResourceType = types.Option{
	Name:        "secret-resource-types",
	Short:       "t",
	Description: "Comma separated list of AWS services. Currently supported types: " + strings.Join(FindSecretsTypes, ", "),
	Required:    true,
	Type:        types.String,
	Value:       "",
	ValueList:   FindSecretsTypes,
}

var AwsResourceIdOpt = types.Option{
	Name:        "resource-id",
	Short:       "i",
	Description: "AWS Cloud Control resource identifier",
	Required:    true,
	Type:        types.String,
	Value:       "",
}

var AwsResourceNameOpt = types.Option{
	Name:        "name",
	Short:       "n",
	Description: "AWS resource name",
	Required:    true,
	Type:        types.String,
	Value:       "",
}

var AwsSummaryServicesOpt = types.Option{
	Name:        "summary",
	Short:       "s",
	Description: "Use the cost explorer API to get a summary of services",
	Required:    false,
	Type:        types.Bool,
	Value:       "",
}

var AwsActionOpt = types.Option{
	Name:        "action",
	Short:       "a",
	Description: "AWS IAM action",
	Required:    true,
	Type:        types.String,
	Value:       "",
}

var AwsProfileOpt = types.Option{
	Name:        "profile",
	Short:       "p",
	Description: "AWS shared credentials profile",
	Required:    false,
	Type:        types.String,
	Value:       "",
}

var AwsProfileListOpt = types.Option{
	Name:        "profile-list",
	Short:       "l",
	Description: "List of AWS shared credentials profiles",
	Required:    false,
	Type:        types.String,
	Value:       "",
}

var AwsScanTypeOpt = types.Option{
	Name:        "scan-type",
	Short:       "s",
	Description: "Scan type - 'full' for all resources or 'summary' for key services",
	Required:    true,
	Type:        types.String,
	Value:       "full",
	ValueList:   []string{"full", "summary"},
}

var AwsCacheDirOpt = types.Option{
	Name:        "cache-dir",
	Description: "Directory to store API response cache files",
	Required:    false,
	Type:        types.String,
	Value:       filepath.Join(os.TempDir(), "aurelian-cache"),
}

var AwsCacheExtOpt = types.Option{
	Name:        "cache-ext",
	Description: "Name of AWS API response cache files extension \nWarning! Changing the cache file extension may lead to unintended file deletion during automatic cache cleanup.",
	Required:    false,
	Type:        types.String,
	Value:       ".aws-cache",
}

var AwsCacheTTLOpt = types.Option{
	Name:        "cache-ttl",
	Description: "TTL for cached responses in seconds",
	Required:    false,
	Type:        types.Int,
	Value:       "3600",
}

var AwsDisableCacheOpt = types.Option{
	Name:        "disable-cache",
	Description: "Disable API response caching",
	Required:    false,
	Type:        types.Bool,
	Value:       "false",
}

var AwsCacheErrorRespOpt = types.Option{
	Name:        "cache-error-resp",
	Description: "Cache error response",
	Required:    false,
	Type:        types.Bool,
	Value:       "false",
}

var AwsCacheErrorRespTypesOpt = types.Option{
	Name:        "cache-error-resp-type",
	Description: "A comma-separated list of strings specifying cache error response types, e.g., TypeNotFoundException, AccessDeniedException. Use all to represent any error.",
	Required:    false,
	Type:        types.String,
	Value:       "",
}

// Native Plugin Options

func AwsRegions() plugin.Parameter {
	return plugin.NewParam[[]string]("regions", "AWS regions to scan",
		plugin.WithDefault([]string{"all"}),
		plugin.WithShortcode("r"))
}

func AwsProfile() plugin.Parameter {
	return plugin.NewParam[string]("profile", "AWS profile to use",
		plugin.WithShortcode("p"))
}

func AwsProfileDir() plugin.Parameter {
	return plugin.NewParam[string]("profile-dir", "Set to override the default AWS profile directory")
}

func AwsResourceType() plugin.Parameter {
	return plugin.NewParam[[]string]("resource-type", "AWS Cloud Control resource type",
		plugin.WithDefault([]string{"all"}),
		plugin.WithShortcode("t"))
}

func AwsResourceArn() plugin.Parameter {
	return plugin.NewParam[[]string]("resource-arn", "AWS Cloud Control resource ARN",
		plugin.WithShortcode("a"),
		plugin.WithRequired())
}

func AwsCacheDir() plugin.Parameter {
	return plugin.NewParam[string]("cache-dir", "Directory to store API response cache files",
		plugin.WithDefault(filepath.Join(os.TempDir(), "aurelian-cache")),
	)
}

func AwsCacheExt() plugin.Parameter {
	return plugin.NewParam[string]("cache-ext", "Name of AWS API response cache files extension",
		plugin.WithDefault(".aws-cache"),
	)
}

func AwsCacheTTL() plugin.Parameter {
	return plugin.NewParam[int]("cache-ttl", "TTL for cached responses in seconds",
		plugin.WithDefault(3600),
	)
}

func AwsCacheErrorTypes() plugin.Parameter {
	return plugin.NewParam[string]("cache-error-resp-type", "A comma-separated list of strings specifying cache error response types, e.g., TypeNotFoundException, AccessDeniedException. Use all to represent any error.")
}

func AwsOrgPoliciesFile() plugin.Parameter {
	return plugin.NewParam[string]("org-policies", "Path to AWS organization policies JSON file from get-org-policies module",
		plugin.WithShortcode("o"),
	)
}

func AwsGaadFile() plugin.Parameter {
	return plugin.NewParam[string]("gaad-file", "Path to AWS GAAD (GetAccountAuthorizationDetails) JSON file from account-auth-details module",
		plugin.WithShortcode("g"),
	)
}

func AwsResourcePoliciesFile() plugin.Parameter {
	return plugin.NewParam[string]("resource-policies-file", "Path to AWS resource policies JSON file from resource-policies module",
		plugin.WithShortcode("rp"),
	)
}

func AwsCacheErrorResp() plugin.Parameter {
	return plugin.NewParam[bool]("cache-error-resp", "Cache error response",
		plugin.WithDefault(false),
	)
}

func AwsDisableCache() plugin.Parameter {
	return plugin.NewParam[bool]("disable-cache", "Disable API response caching",
		plugin.WithDefault(false),
	)
}

func AwsOrgPolicies() plugin.Parameter {
	return plugin.NewParam[string]("org-policies", "Enable organization policies",
		plugin.WithShortcode("op"),
	)
}

func AwsReconBaseOptions() []plugin.Parameter {
	return []plugin.Parameter{
		AwsProfile(),
		AwsProfileDir(),
		AwsCacheDir(),
		AwsCacheExt(),
		AwsCacheTTL(),
		AwsCacheErrorTypes(),
		AwsCacheErrorResp(),
		AwsDisableCache(),
		AwsOpsecLevel(),
	}
}

func AwsCommonReconOptions() []plugin.Parameter {
	baseOpts := AwsReconBaseOptions()
	return append(baseOpts, []plugin.Parameter{
		AwsRegions(),
		AwsResourceType(),
	}...)
}

func AwsAccessKeyId() plugin.Parameter {
	return plugin.NewParam[[]string]("access-key-id", "AWS access key ID",
		plugin.WithShortcode("k"),
		plugin.WithRequired(),
	)
}

func AwsAccountId() plugin.Parameter {
	return plugin.NewParam[[]string]("account-id", "AWS account ID",
		plugin.WithShortcode("i"),
		plugin.WithRequired(),
	)
}

func AwsAction() plugin.Parameter {
	return plugin.NewParam[[]string]("action", "AWS IAM action",
		plugin.WithShortcode("a"),
		plugin.WithRequired(),
	)
}

func AwsRoleArn() plugin.Parameter {
	return plugin.NewParam[string]("role-arn", "AWS Role ARN to assume for console access",
		plugin.WithShortcode("R"),
	)
}

func AwsSessionDuration() plugin.Parameter {
	return plugin.NewParam[int]("duration", "Session duration in seconds (900-3600)",
		plugin.WithShortcode("d"),
		plugin.WithDefault(3600),
	)
}

func AwsMfaToken() plugin.Parameter {
	return plugin.NewParam[string]("mfa-token", "MFA token code for role assumption",
		plugin.WithShortcode("m"),
	)
}

func AwsRoleSessionName() plugin.Parameter {
	return plugin.NewParam[string]("role-session-name", "Name for the assumed role session",
		plugin.WithDefault("aurelian-console-session"),
	)
}

func AwsFederationName() plugin.Parameter {
	return plugin.NewParam[string]("federation-name", "Name for federation token",
		plugin.WithDefault("aurelian-federation"),
	)
}

func AwsCdkQualifiers() plugin.Parameter {
	return plugin.NewParam[[]string]("cdk-qualifiers", "CDK bootstrap qualifiers to check",
		plugin.WithDefault([]string{"hnb659fds"}),
		plugin.WithShortcode("q"),
	)
}

func AwsCdkCheckAllRegions() plugin.Parameter {
	return plugin.NewParam[bool]("cdk-check-all-regions", "Check all regions for CDK roles",
		plugin.WithDefault(false),
	)
}

func AwsOpsecLevel() plugin.Parameter {
	return plugin.NewParam[string]("opsec_level", "Operational security level for AWS operations",
		plugin.WithDefault("none"),
	)
}

func AwsApolloOfflineOptions() []plugin.Parameter {
	baseOpts := AwsReconBaseOptions()
	return append(baseOpts, []plugin.Parameter{
		AwsOrgPoliciesFile(),
		AwsGaadFile(),
		AwsResourcePoliciesFile(),
	}...)
}
