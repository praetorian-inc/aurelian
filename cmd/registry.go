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
	RegisterModule(awsAnalyzeCmd, analyze.AccessKeyIdToAccountIdMetadata, analyze.AwsAccessKeyIdToAccountIdRequiredOptions, noCommon, analyze.NewAccessKeyIdToAccountId)
	RegisterModule(awsAnalyzeCmd, analyze.KnownAccountIDMetadata, analyze.KnownAccountIDRequiredOptions, noCommon, analyze.NewKnownAccountID)
	RegisterModule(awsAnalyzeCmd, analyze.AwsOllamaIamMetadata, analyze.AwsOllamaIamRequiredOptions, noCommon, analyze.NewAwsOllamaIam)
	RegisterModule(awsAnalyzeCmd, analyze.AwsExpandActionsMetadata, analyze.AwsExpandActionsRequiredOptions, noCommon, analyze.NewAwsExpandActions)

	// AWS Recon
	RegisterModule(awsReconCmd, reconaws.AwsSummaryMetadata, reconaws.AwsSummaryRequiredOptions, awsCommonOptions, reconaws.NewAwsSummary)
	RegisterModule(awsReconCmd, reconaws.AwsCloudControlListResourcesMetadata, reconaws.AwsCloudControlListResourcesRequiredOptions, awsCommonOptions, reconaws.NewAwsCloudControlListResources)
	RegisterModule(awsReconCmd, reconaws.AwsCloudControlGetResourceMetadata, reconaws.AwsCloudControlGetResourceRequiredOptions, awsCommonOptions, reconaws.NewAwsCloudControlGetResource)
	RegisterModule(awsReconCmd, reconaws.AwsAuthorizationDetailsMetadata, reconaws.AwsAuthorizationDetailsRequiredOptions, awsCommonOptions, reconaws.NewAwsAuthorizationDetails)
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
