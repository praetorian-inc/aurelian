package cmd

import (
	"os"

	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/modules"
	analyze "github.com/praetorian-inc/nebula/modules/analyze/aws"
	o "github.com/praetorian-inc/nebula/modules/options"
	reconaws "github.com/praetorian-inc/nebula/modules/recon/aws"
	"github.com/spf13/cobra"
)

func init() {
	// AWS Analyze
	RegisterModule(awsAnalyzeCmd, analyze.AccessKeyIdToAccountIdMetadata, analyze.AwsAccessKeyIdToAccountIdOptions, noCommon, analyze.NewAccessKeyIdToAccountId)
	RegisterModule(awsAnalyzeCmd, analyze.KnownAccountIDMetadata, analyze.KnownAccountIDOptions, noCommon, analyze.NewKnownAccountID)
	RegisterModule(awsAnalyzeCmd, analyze.AwsOllamaIamMetadata, analyze.AwsOllamaIamOptions, noCommon, analyze.NewAwsOllamaIam)
	RegisterModule(awsAnalyzeCmd, analyze.AwsExpandActionsMetadata, analyze.AwsExpandActionsOptions, noCommon, analyze.NewAwsExpandActions)
	RegisterModule(awsAnalyzeCmd, analyze.AwsOllamaIamAuditMetadata, analyze.AwsOllamaIamAuditOptions, noCommon, analyze.NewAwsOllamaIamAudit)

	// AWS Recon
	RegisterModule(awsReconCmd, reconaws.AwsSummaryMetadata, reconaws.AwsSummaryOptions, awsCommonOptions, reconaws.NewAwsSummary)
	RegisterModule(awsReconCmd, reconaws.AwsCloudControlListResourcesMetadata, reconaws.AwsCloudControlListResourcesOptions, awsCommonOptions, reconaws.NewAwsCloudControlListResources)
	RegisterModule(awsReconCmd, reconaws.AwsCloudControlGetResourceMetadata, reconaws.AwsCloudControlGetResourceOptions, awsCommonOptions, reconaws.NewAwsCloudControlGetResource)
	RegisterModule(awsReconCmd, reconaws.AwsAuthorizationDetailsMetadata, reconaws.AwsAuthorizationDetailsOptions, awsCommonOptions, reconaws.NewAwsAuthorizationDetails)

	// Azure Recon
	//RegisterModule(azureReconCmd, reconaz.AzureSummaryMetadata, reconaz.AzureSummaryOptions, azureCommonOptions, reconaz.NewAzureSummary)

	// GCP Recon
	//RegisterModule(gcpReconCmd, recongcp.GetProjectsMetadata, recongcp.GetProjectsOptions, noCommon, recongcp.NewGetProjects)
}

var noCommon = []*o.Option{}

func RegisterModule(cmd *cobra.Command, metadata modules.Metadata, required []*o.Option, common []*o.Option, factoryFn func(options []*o.Option, run modules.Run) (modules.Module, error)) {
	c := &cobra.Command{
		Use:   metadata.Id,
		Short: metadata.Description,
		Run: func(cmd *cobra.Command, args []string) {
			// TODO replace with getOpts
			options := getOpts(cmd, required, common)
			run := modules.Run{Data: make(chan modules.Result)}
			m, err := factoryFn(options, run)
			if err != nil {
				logs.ConsoleLogger().Error(err.Error())
				os.Exit(1)
			}
			runModule(m, metadata, options, run)
		},
	}

	options2Flag(required, common, c)
	cmd.AddCommand(c)
}
