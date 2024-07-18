package helpers

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	l "github.com/praetorian-inc/nebula/internal/logging"
)

func GetAWSCfg(region string) (aws.Config, error) {

	cfg, err := config.LoadDefaultConfig(
		context.TODO(),
		config.WithClientLogMode(
			aws.LogRetries|
				aws.LogRequestWithBody|
				aws.LogRequestEventMessage|
				aws.LogResponseEventMessage),
		config.WithLogger(l.Logger()),
		config.WithRegion(region),
	)

	if err != nil {
		return aws.Config{}, err
	}

	return cfg, nil
}
