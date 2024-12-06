package helpers

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/ratelimit"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/types"
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

func GetAWSCfg(region string, profile string) (aws.Config, error) {
	cfg, err := config.LoadDefaultConfig(
		context.TODO(),
		config.WithClientLogMode(
			aws.LogRetries|
				aws.LogRequestWithBody|
				aws.LogRequestEventMessage|
				aws.LogResponseEventMessage),
		config.WithLogger(logs.Logger()),
		config.WithRegion(region),
		config.WithSharedConfigProfile(profile),
		config.WithRetryer(func() aws.Retryer {
			return retry.NewStandard(func(o *retry.StandardOptions) {
				o.Backoff = retry.NewExponentialJitterBackoff(100 * time.Second)
				o.MaxAttempts = 10
				o.MaxBackoff = 100 * time.Second
				o.RateLimiter = ratelimit.NewTokenRateLimit(500)
			})
		}),
	)

	if err != nil {
		return aws.Config{}, err
	}

	return cfg, nil
}

func GetAccountId(cfg aws.Config) (string, error) {
	client := sts.NewFromConfig(cfg)
	input := &sts.GetCallerIdentityInput{}

	result, err := client.GetCallerIdentity(context.TODO(), input)
	if err != nil {
		return "", err
	}

	return *result.Account, nil
}

// Parses regions with 2 primary outcomes
// if "ALL" is provided, then it detects all Enabled Regions
// else it just reads the list of regions provided

func ParseRegionsOption(regionsOpt string, profile string) ([]string, error) {

	if regionsOpt == "ALL" {
		logs.ConsoleLogger().Debug("Gathering enabled regions")
		enabledRegions, err := EnabledRegions(profile)
		if err != nil {
			return nil, err
		}
		logs.ConsoleLogger().Debug("Enabled regions: " + strings.Join(enabledRegions, ", "))
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
