package cmd

import (
	"context"

	"github.com/praetorian-inc/nebula/modules"
	analyze "github.com/praetorian-inc/nebula/modules/analyze/aws"
	o "github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/nebula/stages"
	"github.com/spf13/cobra"
)

func init() {
	// AWS Analyze
	// RegisterModule(awsAnalyzeCmd, analyze.AccessKeyIdToAccountIdMetadata, analyze.AwsAccessKeyIdToAccountIdOptions, noCommon, analyze.NewAccessKeyIdToAccountId)
	// RegisterModule(awsAnalyzeCmd, analyze.KnownAccountIDMetadata, analyze.KnownAccountIDOptions, noCommon, analyze.NewKnownAccountID)
	// RegisterModule(awsAnalyzeCmd, analyze.AwsOllamaIamMetadata, analyze.AwsOllamaIamOptions, noCommon, analyze.NewAwsOllamaIam)
	RegisterModule(awsAnalyzeCmd, analyze.AwsExpandActionsMetadata, analyze.AwsExpandActionsOptions, noCommon, analyze.AwsExpandActionOutputProvders, analyze.NewAwsExpandActions)
	//RegisterModule(awsAnalyzeCmd, analyze.AwsOllamaIamAuditMetadata, analyze.AwsOllamaIamAuditOptions, noCommon, analyze.NewAwsOllamaIamAudit)
	// RegisterModule(awsAnalyzeCmd, analyze.AwsIPLookupMetadata, analyze.AwsIPLookupOptions, noCommon, analyze.NewAwsIPLookup)

	// AWS Recon
	// RegisterModule(awsReconCmd, reconaws.AwsSummaryMetadata, reconaws.AwsSummaryOptions, awsCommonOptions, reconaws.NewAwsSummary)
	// RegisterModule(awsReconCmd, reconaws.AwsCloudControlListResourcesMetadata, reconaws.AwsCloudControlListResourcesOptions, awsCommonOptions, reconaws.NewAwsCloudControlListResources)
	// RegisterModule(awsReconCmd, reconaws.AwsCloudControlGetResourceMetadata, reconaws.AwsCloudControlGetResourceOptions, awsCommonOptions, reconaws.NewAwsCloudControlGetResource)
	// RegisterModule(awsReconCmd, reconaws.AwsAuthorizationDetailsMetadata, reconaws.AwsAuthorizationDetailsOptions, awsCommonOptions, reconaws.NewAwsAuthorizationDetails)
	// RegisterModule(awsReconCmd, reconaws.AwsFindSecretsMetadata, reconaws.AwsFindSecretsOptions, awsCommonOptions, reconaws.NewAwsFindSecrets)
	//RegisterModule(awsReconCmd, reconaws.AwsPublicResourcesMetadata, reconaws.AwsPublicResourcesOptions, awsCommonOptions, reconaws.NewAwsPublicResources)

	// Azure Recon
	//RegisterModule(azureReconCmd, reconaz.AzureSummaryMetadata, reconaz.AzureSummaryOptions, azureCommonOptions, reconaz.NewAzureSummary)

	// GCP Recon
	//RegisterModule(gcpReconCmd, recongcp.GetProjectsMetadata, recongcp.GetProjectsOptions, noCommon, recongcp.NewGetProjects)
}

var noCommon = []*o.Option{}

func RegisterModule[In, Out any](cmd *cobra.Command, metadata modules.Metadata, required []*o.Option, common []*o.Option, outputProviders modules.OutputProviders, sf stages.StageFactory[In, Out]) {
	c := &cobra.Command{
		Use:   metadata.Id,
		Short: metadata.Description,
		Run: func(cmd *cobra.Command, args []string) {
			options := getOpts(cmd, required, common)

			runModule[In, Out](context.Background(), options, outputProviders, sf)
		},
	}

	options2Flag(required, common, c)
	cmd.AddCommand(c)
}
