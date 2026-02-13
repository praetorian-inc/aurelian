package sts

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awssdksts "github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
)

func AssumeRoleCredentials(cfg aws.Config, roleARN string, sessionName string) (*ststypes.Credentials, error) {
	if roleARN == "" {
		return nil, errors.New("role ARN is required")
	}
	if sessionName == "" {
		return nil, errors.New("role session name is required")
	}

	client := awssdksts.NewFromConfig(cfg)
	result, err := client.AssumeRole(context.TODO(), &awssdksts.AssumeRoleInput{
		RoleArn:         aws.String(roleARN),
		RoleSessionName: aws.String(sessionName),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to assume role %s: %w", roleARN, err)
	}

	if result.Credentials == nil {
		return nil, fmt.Errorf("assume role %s returned nil credentials", roleARN)
	}

	return result.Credentials, nil
}
