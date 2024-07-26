package cmd

import (
	"log"
	"os"

	"github.com/praetorian-inc/nebula/modules"
	reconaws "github.com/praetorian-inc/nebula/modules/recon/aws"
	"github.com/spf13/cobra"
)

var awsReconCmd = &cobra.Command{
	Use:   "recon",
	Short: "AWS recon modules",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
		os.Exit(1)
	},
}

var awsSummaryCmd = &cobra.Command{
	Use:   reconaws.AwsSummaryMetadata.Id,
	Short: reconaws.AwsSummaryMetadata.Description,
	Run: func(cmd *cobra.Command, args []string) {
		options := getOpts(cmd, reconaws.AwsSummaryRequiredOptions, awsCommonOptions)
		run := modules.Run{Data: make(chan modules.Result)}
		m, err := reconaws.NewAwsSummary(options, run)
		if err != nil {
			log.Default().Println(err)
			os.Exit(1)
		}
		runModule(m, reconaws.AwsSummaryMetadata, options, run)
	},
}

var awsCloudControlListCommand = &cobra.Command{
	Use:   reconaws.AwsCloudControlListResourcesMetadata.Id,
	Short: reconaws.AwsCloudControlListResourcesMetadata.Description,
	Run: func(cmd *cobra.Command, args []string) {
		options := getOpts(cmd, reconaws.AwsCloudControlListResourcesRequiredOptions, awsCommonOptions)

		run := modules.Run{Data: make(chan modules.Result)}
		m, err := reconaws.NewAwsCloudControlListResources(options, run)
		if err != nil {
			log.Default().Println(err)
			os.Exit(1)
		}

		runModule(m, reconaws.AwsCloudControlListResourcesMetadata, options, run)
	},
}

var awsCloudControlGetCommand = &cobra.Command{
	Use:   reconaws.AwsCloudControlGetResourceMetadata.Id,
	Short: reconaws.AwsCloudControlGetResourceMetadata.Description,
	Run: func(cmd *cobra.Command, args []string) {
		options := getOpts(cmd, reconaws.AwsCloudControlGetResourceRequiredOptions, awsCommonOptions)

		run := modules.Run{Data: make(chan modules.Result)}
		m, err := reconaws.NewAwsCloudControlGetResource(options, run)
		if err != nil {
			log.Default().Println(err)
			os.Exit(1)
		}
		runModule(m, reconaws.AwsCloudControlGetResourceMetadata, options, run)
	},
}

/*
var awsListAllResourcesCmd = &cobra.Command{
	Use:   reconaws.AwsListAllResourcesMetadata.Id,
	Short: reconaws.AwsListAllResourcesMetadata.Description,
	Run: func(cmd *cobra.Command, args []string) {
		options := getGlobalOpts(cmd)
		run := modules.Run{Data: make(chan modules.Result)}
		m, err := reconaws.NewAwsListAllResources(options, run)
		if err != nil {
			log.Default().Println(err)
			os.Exit(1)
		}
		runModule(m, reconaws.AwsListAllResourcesMetadata, options, run)
	},
}
*/

var awsGetAuthorizationDetailsCommand = &cobra.Command{
	Use:   reconaws.AwsAuthorizationDetailsMetadata.Id,
	Short: reconaws.AwsAuthorizationDetailsMetadata.Description,
	Run: func(cmd *cobra.Command, args []string) {
		options := getOpts(cmd, reconaws.AwsAuthorizationDetailsRequiredOptions, awsCommonOptions)

		run := modules.Run{Data: make(chan modules.Result)}
		m, err := reconaws.NewAwsAuthorizationDetails(options, run)
		if err != nil {
			log.Default().Println(err)
			os.Exit(1)
		}
		runModule(m, reconaws.AwsAuthorizationDetailsMetadata, options, run)
	},
}

func init() {
	awsReconCmd.AddCommand(awsSummaryCmd)

	options2Flag(reconaws.AwsCloudControlListResourcesRequiredOptions, awsCommonOptions, awsCloudControlListCommand)
	awsReconCmd.AddCommand(awsCloudControlListCommand)

	options2Flag(reconaws.AwsCloudControlGetResourceRequiredOptions, awsCommonOptions, awsCloudControlGetCommand)
	awsReconCmd.AddCommand(awsCloudControlGetCommand)

	options2Flag(reconaws.AwsAuthorizationDetailsRequiredOptions, awsCommonOptions, awsGetAuthorizationDetailsCommand)
	awsReconCmd.AddCommand(awsGetAuthorizationDetailsCommand)

	//options2Flag(reconaws.AwsListAllResourcesRequiredOptions, commonOptions, awsListAllResourcesCmd)
	//awsReconCmd.AddCommand(awsListAllResourcesCmd)

	awsCmd.AddCommand(awsReconCmd)
}
