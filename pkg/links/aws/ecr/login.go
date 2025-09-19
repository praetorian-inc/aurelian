package ecr

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/docker/docker/api/types/registry"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	dockerTypes "github.com/praetorian-inc/janus-framework/pkg/types/docker"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
)

type AWSECRLogin struct {
	*base.AwsReconLink
}

func NewAWSECRLogin(configs ...cfg.Config) chain.Link {
	ecrLogin := &AWSECRLogin{}
	ecrLogin.AwsReconLink = base.NewAwsReconLink(ecrLogin, configs...)
	return ecrLogin
}

func (a *AWSECRLogin) Process(registryURL string) error {
	region, err := ExtractRegion(registryURL)
	if err != nil {
		return err
	}

	config, err := a.GetConfigWithRuntimeArgs(region)
	if err != nil {
		slog.Error("Failed to get AWS config", "error", err)
		return nil
	}

	account, err := helpers.GetAccountId(config)
	if err != nil {
		slog.Error("Failed to get account ID", "error", err)
		return nil
	}

	jwt, err := a.authenticate(config)
	if err != nil {
		return err
	}

	ic := dockerTypes.DockerImage{
		AuthConfig: registry.AuthConfig{
			Username:      "AWS",
			Password:      string(jwt),
			ServerAddress: fmt.Sprintf("https://%s.dkr.ecr.%s.amazonaws.com", account, region),
		},
		Image: registryURL,
	}
	a.Send(ic)

	return nil
}

func (a *AWSECRLogin) authenticate(config aws.Config) (string, error) {
	client := ecr.NewFromConfig(config)
	input := &ecr.GetAuthorizationTokenInput{}
	tokenOutput, err := client.GetAuthorizationToken(a.Context(), input)
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
