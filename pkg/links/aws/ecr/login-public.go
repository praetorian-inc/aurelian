package ecr

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/service/ecrpublic"
	"github.com/docker/docker/api/types/registry"
	"github.com/praetorian-inc/aurelian/pkg/links/aws/base"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

type AWSECRLoginPublic struct {
	*base.NativeAWSLink
}

func NewAWSECRLoginPublic(args map[string]any) *AWSECRLoginPublic {
	return &AWSECRLoginPublic{
		NativeAWSLink: base.NewNativeAWSLink("ecr-login-public", args),
	}
}

func (a *AWSECRLoginPublic) Process(ctx context.Context, input any) ([]any, error) {
	repositoryURI, ok := input.(string)
	if !ok {
		return nil, fmt.Errorf("expected string, got %T", input)
	}

	region, err := ExtractRegion(repositoryURI)
	if err != nil {
		return nil, err
	}

	config, err := a.GetConfig(ctx, region)
	if err != nil {
		slog.Error("Failed to get AWS config", "error", err)
		return nil, err
	}

	client := ecrpublic.NewFromConfig(config)
	tokenInput := &ecrpublic.GetAuthorizationTokenInput{}
	tokenOutput, err := client.GetAuthorizationToken(ctx, tokenInput)
	if err != nil {
		slog.Error("Failed to get authorization token", "error", err)
		return nil, err
	}

	token := tokenOutput.AuthorizationData.AuthorizationToken
	parsed, err := base64.StdEncoding.DecodeString(*token)
	if err != nil {
		slog.Debug("Failed to decode authorization token", "error", err)
		return nil, err
	}

	image := types.DockerImage{
		AuthConfig: registry.AuthConfig{
			Username:      "AWS",
			Password:      string(parsed),
			ServerAddress: fmt.Sprintf("https://public.ecr.aws"),
		},
		Image: repositoryURI,
	}

	return []any{image}, nil
}
