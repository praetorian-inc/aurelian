package stages

import (
	"context"
	"encoding/base64"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/types"
)

func AwsCloudFormationGetTemplatesNpInputStage(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.NpInput {
	out := make(chan types.NpInput)

	go func() {
		defer close(out)
		for erd := range in {
			for template := range AwsCloudFormationGetTemplateStage(ctx, opts, Generator[types.EnrichedResourceDescription]([]types.EnrichedResourceDescription{erd})) {
				encodedTemplate := base64.StdEncoding.EncodeToString([]byte(template))
				out <- types.NpInput{
					ContentBase64: encodedTemplate,
					Provenance: types.NpProvenance{
						Platform:     "aws",
						ResourceType: "AWS::CloudFormation::Template",
						ResourceID:   erd.Identifier,
						Region:       erd.Region,
						AccountID:    erd.AccountId,
					},
				}
			}
		}
	}()

	return out
}

func AwsCloudFormationGetTemplateStage(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan string {
	logger := logs.NewStageLogger(ctx, opts, "GetCFTemplatesStage")
	out := make(chan string)

	go func() {
		defer close(out)
		for data := range in {
			cfg, err := helpers.GetAWSCfg(data.Region, options.GetOptionByName("profile", opts).Value, opts)
			if err != nil {
				logger.Error(err.Error())
				continue
			}

			cf := cloudformation.NewFromConfig(cfg)
			template, err := cf.GetTemplate(ctx, &cloudformation.GetTemplateInput{
				StackName: &data.Identifier,
			})

			if err != nil {
				logger.Error(err.Error())
				continue
			}

			logger.Debug("Retrieved CloudFormation template", slog.String("stack", "data.Identifier"), slog.String("template", *template.TemplateBody))
			out <- *template.TemplateBody
		}
	}()

	return out
}
