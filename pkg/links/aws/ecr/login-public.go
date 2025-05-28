package ecr

import (
	"encoding/base64"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/service/ecrpublic"
	"github.com/docker/docker/api/types/registry"
	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	jtypes "github.com/praetorian-inc/janus/pkg/types"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
)

type AWSECRLoginPublic struct {
	*base.AwsReconLink
}

func NewAWSECRLoginPublic(configs ...cfg.Config) chain.Link {
	elp := &AWSECRLoginPublic{}
	elp.AwsReconLink = base.NewAwsReconLink(elp, configs...)
	return elp
}

func (a *AWSECRLoginPublic) Process(repositoryURI string) error {
	region, err := ExtractRegion(repositoryURI)
	if err != nil {
		return err
	}

	config, err := a.GetConfigWithRuntimeArgs(region)
	if err != nil {
		slog.Error("Failed to get AWS config", "error", err)
		return nil
	}

	client := ecrpublic.NewFromConfig(config)
	input := &ecrpublic.GetAuthorizationTokenInput{}
	tokenOutput, err := client.GetAuthorizationToken(a.Context(), input)
	if err != nil {
		slog.Error("Failed to get authorization token", "error", err)
		return nil
	}

	token := tokenOutput.AuthorizationData.AuthorizationToken
	parsed, err := base64.StdEncoding.DecodeString(*token)
	if err != nil {
		slog.Debug("Failed to decode authorization token", "error", err)
		return nil
	}

	image := jtypes.DockerImage{
		AuthConfig: registry.AuthConfig{
			Username:      "AWS",
			Password:      string(parsed),
			ServerAddress: fmt.Sprintf("public.ecr.aws"),
		},
		Image: repositoryURI,
	}

	return a.Send(image)
}
