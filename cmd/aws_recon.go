package cmd

import (
	"fmt"
	"log"
	"os"

	"github.com/praetorian-inc/nebula/modules"
	o "github.com/praetorian-inc/nebula/modules/options"
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

func AwsEnum(cmd *cobra.Command, args []string) {

	fmt.Println("AWS Enum")
}

var awsSummaryCmd = &cobra.Command{
	Use:   reconaws.AwsSummaryMetadata.Id,
	Short: reconaws.AwsSummaryMetadata.Description,
	Run: func(cmd *cobra.Command, args []string) {
		options := getGlobalOpts(cmd)
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
		options := getGlobalOpts(cmd)

		regions := o.AwsRegionsOpt
		regions.Value, _ = cmd.Flags().GetString(regions.Name)
		options = append(options, &regions)

		rtype := o.AwsResourceTypeOpt
		rtype.Value, _ = cmd.Flags().GetString(rtype.Name)
		options = append(options, &rtype)

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
		options := getGlobalOpts(cmd)

		region := o.AwsRegionOpt
		region.Value, _ = cmd.Flags().GetString(region.Name)
		options = append(options, &region)

		rtype := o.AwsResourceTypeOpt
		rtype.Value, _ = cmd.Flags().GetString(rtype.Name)
		options = append(options, &rtype)

		id := o.AwsResourceIdOpt
		id.Value, _ = cmd.Flags().GetString(id.Name)
		options = append(options, &id)

		run := modules.Run{Data: make(chan modules.Result)}
		m, err := reconaws.NewAwsCloudControlGetResource(options, run)
		if err != nil {
			log.Default().Println(err)
			os.Exit(1)
		}
		runModule(m, reconaws.AwsCloudControlGetResourceMetadata, options, run)
	},
}

var awsGetAuthorizationDetailsCommand = &cobra.Command{
	Use:   reconaws.AwsAuthorizationDetailsMetadata.Id,
	Short: reconaws.AwsAuthorizationDetailsMetadata.Description,
	Run: func(cmd *cobra.Command, args []string) {
		options := getGlobalOpts(cmd)

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

	option2Flag(&o.AwsRegionsOpt, awsCloudControlListCommand)
	option2Flag(&o.AwsResourceTypeOpt, awsCloudControlListCommand)
	awsReconCmd.AddCommand(awsCloudControlListCommand)

	option2Flag(&o.AwsRegionOpt, awsCloudControlGetCommand)
	option2Flag(&o.AwsResourceTypeOpt, awsCloudControlGetCommand)
	option2Flag(&o.AwsResourceIdOpt, awsCloudControlGetCommand)
	awsReconCmd.AddCommand(awsCloudControlGetCommand)

	awsReconCmd.AddCommand(awsGetAuthorizationDetailsCommand)

	awsCmd.AddCommand(awsReconCmd)
}
