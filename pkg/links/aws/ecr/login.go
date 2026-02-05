package ecr

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/docker/docker/api/types/registry"
	"github.com/praetorian-inc/aurelian/internal/helpers"
	"github.com/praetorian-inc/aurelian/pkg/links/aws/base"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

type AWSECRLogin struct {
	*base.NativeAWSLink
}

func NewAWSECRLogin(args map[string]any) *AWSECRLogin {
	return &AWSECRLogin{
		NativeAWSLink: base.NewNativeAWSLink("ecr-login", args),
	}
}

func (a *AWSECRLogin) Process(ctx context.Context, input any) ([]any, error) {
	registryURL, ok := input.(string)
	if !ok {
		return nil, fmt.Errorf("expected string, got %T", input)
	}

	region, err := ExtractRegion(registryURL)
	if err != nil {
		return nil, err
	}

	config, err := a.GetConfig(ctx, region)
	if err != nil {
		slog.Error("Failed to get AWS config", "error", err)
		return nil, err
	}

	account, err := helpers.GetAccountId(config)
	if err != nil {
		slog.Error("Failed to get account ID", "error", err)
		return nil, err
	}

	jwt, err := a.authenticate(ctx, config)
	if err != nil {
		return nil, err
	}

	ic := types.DockerImage{
		AuthConfig: registry.AuthConfig{
			Username:      "AWS",
			Password:      string(jwt),
			ServerAddress: fmt.Sprintf("https://%s.dkr.ecr.%s.amazonaws.com", account, region),
		},
		Image: registryURL,
	}

	return []any{ic}, nil
}

func (a *AWSECRLogin) authenticate(ctx context.Context, config aws.Config) (string, error) {
	client := ecr.NewFromConfig(config)
	input := &ecr.GetAuthorizationTokenInput{}
	tokenOutput, err := client.GetAuthorizationToken(ctx, input)
	if err != nil {
		return "", fmt.Errorf("authentication error: %w", err)
	}

	token := tokenOutput.AuthorizationData[0].AuthorizationToken
	parsed, err := base64.StdEncoding.DecodeString(*token)
	if err != nil {
		return "", fmt.Errorf("decoding error: %w", err)
	}

	if !strings.Contains(string(parsed), ":") {
		return "", fmt.Errorf("invalid Docker JWT")
	}

	jwt := strings.Split(string(parsed), ":")[1]
	return jwt, nil
}
