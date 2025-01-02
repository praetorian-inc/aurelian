package cmd

import (
	"context"

	"github.com/praetorian-inc/nebula/modules"
	analyze "github.com/praetorian-inc/nebula/modules/analyze/aws"
	augment "github.com/praetorian-inc/nebula/modules/misc/augment"
	recon "github.com/praetorian-inc/nebula/modules/recon/aws"
	"github.com/praetorian-inc/nebula/pkg/stages"
	"github.com/praetorian-inc/nebula/pkg/types"
	"github.com/spf13/cobra"
)

func init() {
	// AWS Analyze
	RegisterModule(awsAnalyzeCmd, analyze.AccessKeyIdToAccountIdMetadata, analyze.AwsAccessKeyIdToAccountIdOptions, noCommon, analyze.AwsAccessKeyIdToAccountIdOutputProviders, analyze.NewAccessKeyIdToAccountId)
	RegisterModule(awsAnalyzeCmd, analyze.KnownAccountIDMetadata, analyze.KnownAccountIDOptions, noCommon, analyze.KnownAccountIDOutputProviders, analyze.NewKnownAccountID)
	RegisterModule(awsAnalyzeCmd, analyze.AwsOllamaIamMetadata, analyze.AwsOllamaIamOptions, noCommon, analyze.AwsOllamaIamOutputProviders, analyze.NewAwsOllamaIam)
	RegisterModule(awsAnalyzeCmd, analyze.AwsExpandActionsMetadata, analyze.AwsExpandActionsOptions, noCommon, analyze.AwsExpandActionOutputProvders, analyze.NewAwsExpandActions)
	//RegisterModule(awsAnalyzeCmd, analyze.AwsOllamaIamAuditMetadata, analyze.AwsOllamaIamAuditOptions, noCommon, analyze.AwsOllamaIamAuditOutputProviders, analyze.NewAwsOllamaIamAudit)
	RegisterModule(awsAnalyzeCmd, analyze.AwsIPLookupMetadata, analyze.AwsIPLookupOptions, noCommon, analyze.AwsIPLookupOutputProviders, analyze.NewAwsIPLookup)

	// AWS Recon
	// RegisterModule(awsReconCmd, recon.AwsSummaryMetadata, recon.AwsSummaryOptions, awsCommonOptions, recon.NewAwsSummary)
	RegisterModule(awsReconCmd, recon.AwsCloudControlListResourcesMetadata, recon.AwsCloudControlListResourcesOptions, awsCommonOptions, recon.AwsCloudControlListResourcesOutputProviders, recon.NewAwsCloudControlListResources)
	RegisterModule(awsReconCmd, recon.AwsCloudControlGetResourceMetadata, recon.AwsCloudControlGetResourceOptions, awsCommonOptions, recon.AwsCloudControlGetResourceOutputProviders, recon.NewAwsCloudControlGetResource)
	RegisterModule(awsReconCmd, recon.AwsAuthorizationDetailsMetadata, recon.AwsAuthorizationDetailsOptions, awsCommonOptions, recon.AwsAuthorizationDetailsOutputProviders, recon.NewAwsAuthorizationDetails)
	// RegisterModule(awsReconCmd, recon.AwsFindSecretsMetadata, recon.AwsFindSecretsOptions, awsCommonOptions, recon.NewAwsFindSecrets)
	RegisterModule(awsReconCmd, recon.AwsPublicResourcesMetadata, recon.AwsPublicResourcesOptions, awsCommonOptions, recon.AwsPublicResourcesOutputProviders, recon.NewAwsPublicResources)
	RegisterModule(awsReconCmd, recon.AwsListAllResourcesMetadata, recon.AwsListAllResourcesOptions, awsCommonOptions, recon.AwsListAllResourcesOutputProviders, recon.NewAwsListAllResources)

	// Azure Recon
	//RegisterModule(azureReconCmd, reconaz.AzureSummaryMetadata, reconaz.AzureSummaryOptions, azureCommonOptions, reconaz.NewAzureSummary)

	// GCP Recon
	//RegisterModule(gcpReconCmd, recongcp.GetProjectsMetadata, recongcp.GetProjectsOptions, noCommon, recongcp.NewGetProjects)

	// Misc Modules
	RegisterModule(miscAugmentCmd, augment.MiscProwlerToMDTableMetadata, augment.MiscProwlerToMDTableOptions, miscCommonOptions, augment.MiscProwlerToMDTableOutputProviders, augment.NewMiscProwlerToMDTable)
}

var noCommon = []*types.Option{}

func RegisterModule[In, Out any](cmd *cobra.Command, metadata modules.Metadata, required []*types.Option, common []*types.Option, outputProviders types.OutputProviders, sf stages.StageFactory[In, Out]) {
	c := &cobra.Command{
		Use:   metadata.Id,
		Short: metadata.Description,
		Run: func(cmd *cobra.Command, args []string) {
			options := getOpts(cmd, required, common)

			runModule[In, Out](context.Background(), metadata, options, outputProviders, sf)
		},
	}

	options2Flag(required, common, c)
	cmd.AddCommand(c)
}
