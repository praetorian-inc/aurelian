package helpers

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/praetorian-inc/nebula/internal/logs"
)

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
