package helpers

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	logs "github.com/praetorian-inc/nebula/internal/logs"
)

func GetAWSCfg(region string) (aws.Config, error) {

	cfg, err := config.LoadDefaultConfig(
		context.TODO(),
		config.WithClientLogMode(
			aws.LogRetries|
				aws.LogRequestWithBody|
				aws.LogRequestEventMessage|
				aws.LogResponseEventMessage),
		config.WithLogger(logs.Logger()),
		config.WithRegion(region),
	)

	if err != nil {
		return aws.Config{}, err
	}

	return cfg, nil
}
