package helpers

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/praetorian-inc/nebula/internal/logs"
)

type ArnIdentifier struct {
	ARN       string
	Partition string
	Service   string
	Region    string
	AccountID string
	Resource  string
}

func NewArn(identifier string) (ArnIdentifier, error) {
	valid, err := validateARN(identifier)
	if err != nil {
		return ArnIdentifier{}, err
	}
	if !valid {
		return ArnIdentifier{}, fmt.Errorf("this is not a valid arn %v", identifier)
	}

	var arn ArnIdentifier
	parts := strings.Split(identifier, ":")

	// The last part after the service and region parts should start with "stack/"
	arn.ARN = identifier
	arn.Partition = parts[1]
	arn.Service = parts[2]
	arn.Region = parts[3]
	arn.AccountID = parts[4]
	arn.Resource = parts[5]
	return arn, nil
}

func MakeArnIdentifiers(identifiers []string) ([]ArnIdentifier, error) {
	var ArnIdentifiers []ArnIdentifier
	for _, identifier := range identifiers {
		arn, err := NewArn(identifier)
		if err != nil {
			return nil, err
		}
		ArnIdentifiers = append(ArnIdentifiers, arn)
	}
	return ArnIdentifiers, nil
}

func MapArnByRegions(identifiers []string) (map[string][]ArnIdentifier, error) {
	regionToArnIdentifiers := make(map[string][]ArnIdentifier)
	for _, identifier := range identifiers {
		arn, err := NewArn(identifier)
		if err != nil {
			return nil, err
		}
		regionToArnIdentifiers[arn.Region] = append(regionToArnIdentifiers[arn.Region], arn)
	}
	return regionToArnIdentifiers, nil
}

func validateARN(arn string) (bool, error) {
	// Define the regex pattern for a valid ARN
	var arnRegex = `^arn:(aws|aws-cn|aws-us-gov):[a-zA-Z0-9-]+:[a-zA-Z0-9-]*:\d{12}:[^:]+$`

	// Compile the regex
	re, err := regexp.Compile(arnRegex)
	if err != nil {
		return false, fmt.Errorf("failed to compile regex: %v", err)
	}

	// Validate the ARN
	isValid := re.MatchString(arn)
	return isValid, nil
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
		logs.ConsoleLogger().Info("Gathering enabled regions")
		enabledRegions, err := EnabledRegions(profile)
		if err != nil {
			return nil, err
		}
		return enabledRegions, nil
	} else {
		regions := strings.Split(regionsOpt, ",")
		return regions, nil
	}
}

func ParseSecretsResourceType(regionsOpt string, profile string) ([]string, error) {

	if regionsOpt == "ALL" {
		logs.ConsoleLogger().Info("Gathering enabled regions")
		enabledRegions, err := EnabledRegions(profile)
		if err != nil {
			return nil, err
		}
		return enabledRegions, nil
	} else {
		regions := strings.Split(regionsOpt, ",")
		return regions, nil
	}
}

func CreateFilePath(cloudProvider, service, account, command, region, resource string) string {
	return fmt.Sprintf("%s%s%s%s%s%s%s-%s-%s.json", cloudProvider, string(os.PathSeparator), service, string(os.PathSeparator), account, string(os.PathSeparator), command, region, resource)
}
