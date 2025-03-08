package aws

import (
	"encoding/base64"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	jtypes "github.com/praetorian-inc/janus/pkg/types"
	"github.com/praetorian-inc/janus/pkg/util"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type AWSCloudFormationTemplates struct {
	AwsReconLink
}

func NewAWSCloudFormationTemplates(configs ...cfg.Config) chain.Link {
	cf := &AWSCloudFormationTemplates{}
	cf.Base = chain.NewBase(cf, configs...)
	return cf
}

func (a *AWSCloudFormationTemplates) Process(resource *types.EnrichedResourceDescription) error {
	config, err := util.GetAWSConfig(resource.Region, a.profile)
	if err != nil {
		slog.Error("Failed to get AWS config for region", "region", resource.Region, "error", err)
		return nil
	}

	client := cloudformation.NewFromConfig(config)

	template, err := client.GetTemplate(a.Context(), &cloudformation.GetTemplateInput{
		StackName: &resource.Identifier,
	})

	if err != nil {
		slog.Error("Failed to get template", "error", err)
		return nil
	}

	encoded := base64.StdEncoding.EncodeToString([]byte(*template.TemplateBody))

	return a.Send(jtypes.NPInput{
		ContentBase64: encoded,
		Provenance: jtypes.NPProvenance{
			Platform:     "aws",
			ResourceType: "AWS::CloudFormation::Template",
		},
	})
}
