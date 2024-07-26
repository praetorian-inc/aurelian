package cmd

import (
	"log"
	"os"

	"github.com/praetorian-inc/nebula/modules"
	analyze "github.com/praetorian-inc/nebula/modules/analyze/aws"
	o "github.com/praetorian-inc/nebula/modules/options"
	"github.com/spf13/cobra"
)

var awsAnalyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "aws analyze modules",
	Long:  `Execute aws analyze modules.`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
		os.Exit(1)
	},
}

var awsAccessKeyIdToAccountIdCmd = &cobra.Command{
	Use:   analyze.AccessKeyIdToAccountIdMetadata.Id,
	Short: analyze.AccessKeyIdToAccountIdMetadata.Description,
	Run: func(cmd *cobra.Command, args []string) {
		options := getGlobalOpts(cmd)

		akid := o.AwsAccessKeyIdOpt
		akid.Value, _ = cmd.Flags().GetString(akid.Name)
		options = append(options, &akid)

		run := modules.Run{Data: make(chan modules.Result)}
		m, err := analyze.NewAccessKeyIdToAccountId(options, run)
		if err != nil {
			log.Default().Println(err)
			os.Exit(1)
		}

		runModule(m, analyze.AccessKeyIdToAccountIdMetadata, options, run)
	},
}

var awsKnownAccountIdCmd = &cobra.Command{
	Use:   analyze.KnownAccountIDMetadata.Id,
	Short: analyze.KnownAccountIDMetadata.Description,
	Run: func(cmd *cobra.Command, args []string) {
		options := getGlobalOpts(cmd)

		aid := o.AwsAccountIdOpt
		aid.Value, _ = cmd.Flags().GetString(aid.Name)
		options = append(options, &aid)

		run := modules.Run{Data: make(chan modules.Result)}
		m, err := analyze.NewKnownAccountID(options, run)
		if err != nil {
			log.Default().Println(err)
			os.Exit(1)
		}

		runModule(m, analyze.KnownAccountIDMetadata, options, run)
	},
}

var awsOllamaIamCmd = &cobra.Command{
	Use:   analyze.AwsOllamaIamMetadata.Id,
	Short: analyze.AwsOllamaIamMetadata.Description,
	Run: func(cmd *cobra.Command, args []string) {

		options := getOpts(cmd, analyze.AwsOllamaIamRequiredOptions)
		run := modules.Run{Data: make(chan modules.Result)}
		m, err := analyze.NewAwsOllamaIam(options, run)
		if err != nil {
			log.Default().Println(err)
			os.Exit(1)
		}

		runModule(m, analyze.AwsOllamaIamMetadata, options, run)
	},
}

var awsExpandActionsCmd = &cobra.Command{
	Use:   analyze.AwsExpandActionsMetadata.Id,
	Short: analyze.AwsExpandActionsMetadata.Description,
	Run: func(cmd *cobra.Command, args []string) {

		options := getOpts(cmd, analyze.AwsExpandActionsRequiredOptions)
		run := modules.Run{Data: make(chan modules.Result)}
		m, err := analyze.NewAwsExpandActions(options, run)
		if err != nil {
			log.Default().Println(err)
			os.Exit(1)
		}

		runModule(m, analyze.AwsExpandActionsMetadata, options, run)
	},
}

func init() {
	options2Flag(analyze.AccessKeyIdToAccountIdRequiredOptions, awsAccessKeyIdToAccountIdCmd)
	awsAnalyzeCmd.AddCommand(awsAccessKeyIdToAccountIdCmd)

	options2Flag(analyze.KnownAccountIDRequiredOptions, awsKnownAccountIdCmd)
	awsAnalyzeCmd.AddCommand(awsKnownAccountIdCmd)

	options2Flag(analyze.AwsOllamaIamRequiredOptions, awsOllamaIamCmd)
	awsAnalyzeCmd.AddCommand(awsOllamaIamCmd)

	options2Flag(analyze.AwsExpandActionsRequiredOptions, awsExpandActionsCmd)
	awsAnalyzeCmd.AddCommand(awsExpandActionsCmd)

	awsCmd.AddCommand(awsAnalyzeCmd)
}
