package helpers

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go/middleware"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/types"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

// TODO this should be combined with roseta
const (
	CCCloudFormationStack string = "AWS::CloudFormation::Stack"
	CCEc2Instance         string = "AWS::EC2::Instance"
	CCEcs                 string = "AWS::ECS::TaskDefinition"
	CCSsmDocument         string = "AWS::SSM::Document"
)

var CloudControlTypeNames = map[string]string{
	"AWS::CloudFormation::Stack": "cloudformation",
	"AWS::S3::Bucket":            "s3",
	"AWS::EC2::Instance":         "ec2",
	"AWS::Lambda::Function":      "lambda",
	"AWS::DynamoDB::Table":       "dynamodb",
	"AWS::RDS::DBInstance":       "rds",
}

type ArnIdentifier struct {
	ARN       string
	Partition string
	Service   string
	Region    string
	AccountID string
	Resource  string
}

var ProfileIdentity sync.Map

func NewArn(identifier string) (arn.ARN, error) {
	valid := arn.IsARN(identifier)
	if !valid {
		return arn.ARN{}, fmt.Errorf("this is not a valid arn %v", identifier)
	}

	a, err := arn.Parse(identifier)
	if err != nil {
		return arn.ARN{}, err
	}

	return a, nil
}

func MakeArnIdentifiers(identifiers []string) ([]arn.ARN, error) {
	var arnIdentifiers []arn.ARN
	for _, identifier := range identifiers {
		arn, err := NewArn(identifier)
		if err != nil {
			return nil, err
		}
		arnIdentifiers = append(arnIdentifiers, arn)
	}
	return arnIdentifiers, nil
}

// Useful if identifier returned from CloudControl API is an ARN
func MapArnByRegions(identifiers []string) (map[string][]arn.ARN, error) {
	regionToArnIdentifiers := make(map[string][]arn.ARN)
	for _, identifier := range identifiers {
		arn, err := NewArn(identifier)
		if err != nil {
			return nil, err
		}
		regionToArnIdentifiers[arn.Region] = append(regionToArnIdentifiers[arn.Region], arn)
	}
	return regionToArnIdentifiers, nil
}

// Some resources do not return ARN as identifiers so need to be processed differently
func MapIdentifiersByRegions(resourceDescriptions []types.EnrichedResourceDescription) map[string][]string {
	regionToIdentifiers := make(map[string][]string)
	for _, description := range resourceDescriptions {
		regionToIdentifiers[description.Region] = append(regionToIdentifiers[description.Region], description.Identifier)
	}
	return regionToIdentifiers
}

func GetAWSCfg(region string, profile string, opts []*types.Option) (aws.Config, error) {
	if !cacheMaintained {
		InitCacheCleanup(opts)
		cacheMaintained = true
	}
	
	cfg, err := config.LoadDefaultConfig(
		context.TODO(),
		config.WithClientLogMode(
			aws.LogRetries|
				aws.LogRequestWithBody|
				aws.LogRequestEventMessage|
				aws.LogResponseEventMessage),
		config.WithLogger(logs.AwsCliLogger()),
		config.WithRegion(region),
		config.WithSharedConfigProfile(profile),
		config.WithRetryMode(aws.RetryModeAdaptive),
		// config.WithAPIOptions(cacheFunc),
	)
	if err != nil {
		return aws.Config{}, err
	}
	var principal sts.GetCallerIdentityOutput
	if value, ok := ProfileIdentity.Load(profile); ok {
		principal = value.(sts.GetCallerIdentityOutput)
		slog.Debug("Loaded Profile ARN from Cached Map", "profile", profile, "ARN", *principal.Arn)
	} else {
		principal, err = GetCallerIdentity(cfg)
		atomic.AddInt64(&cacheBypassedCount, 1)
		if err != nil {
			return aws.Config{}, err
		}
		ProfileIdentity.Store(profile, principal)
		slog.Debug("Called STS GetCallerIdentity for", "profile", profile, "ARN", principal.Arn)
	}

	CachePrep := GetCachePrepWithIdentity(principal, opts)

	cfg.APIOptions = append(cfg.APIOptions, func(stack *middleware.Stack) error {
		// Add custom middlewares
		if err := stack.Initialize.Add(CachePrep, middleware.After); err != nil {
			return err
		}
		if err := stack.Deserialize.Add(CacheOps, middleware.After); err != nil {
			return err
		}
		return nil
	})

	return cfg, nil

}

func GetAccountId(cfg aws.Config) (string, error) {
	if strings.ToLower(cfg.Region) == "all" {
		cfg.Region = "us-east-1"
	}
	client := sts.NewFromConfig(cfg)
	input := &sts.GetCallerIdentityInput{}

	result, err := client.GetCallerIdentity(context.TODO(), input)
	if err != nil {
		return "", err
	}

	return *result.Account, nil
}

func GetCallerIdentity(cfg aws.Config) (sts.GetCallerIdentityOutput, error) {
	// Force to use us-east-1 for STS
	// https://docs.aws.amazon.com/sdkref/latest/guide/feature-sts-regionalized-endpoints.html
	cfg.Region = "us-east-1"
	client := sts.NewFromConfig(cfg)
	input := &sts.GetCallerIdentityInput{}

	result, err := client.GetCallerIdentity(context.TODO(), input)
	if err != nil {
		return sts.GetCallerIdentityOutput{}, err
	}

	return *result, nil
}

// Parses regions with 2 primary outcomes
// if "ALL" is provided, then it detects all Enabled Regions
// else it just reads the list of regions provided

func ParseRegionsOption(regionsOpt string, profile string, opts []*types.Option) ([]string, error) {
	slog.Debug("ParseRegionsOption", "regionsOpt", strings.ToLower(regionsOpt))
	if strings.ToLower(regionsOpt) == "all" {
		slog.Debug("Gathering enabled regions")
		enabledRegions, err := EnabledRegions(profile, opts)
		if err != nil {
			return nil, err
		}
		slog.Debug("Enabled regions: " + strings.Join(enabledRegions, ", "))
		return enabledRegions, nil
	} else {
		regions := strings.Split(regionsOpt, ",")
		return regions, nil
	}
}

func ParseSecretsResourceType(secretsOpt string) []string {

	allSupportedTypes := options.AwsFindSecretsResourceType.ValueList
	var resourceTypes []string
	if secretsOpt == "ALL" {
		resourceTypes = allSupportedTypes
	} else {
		resourceTypes = strings.Split(secretsOpt, ",")
	}
	return resourceTypes

}

// TODO this needs to use the `output` parameter for the leading path segment
func CreateFilePath(cloudProvider, service, account, command, region, resource string) string {
	return fmt.Sprintf("%s%s%s%s%s%s%s-%s-%s.json", cloudProvider, string(os.PathSeparator), service, string(os.PathSeparator), account, string(os.PathSeparator), command, region, resource)
}

func CreateFileName(parts ...string) string {
	return strings.Join(parts, "-")
}
