package cmd

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"

	"github.com/praetorian-inc/nebula/modules"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/stages"
	"github.com/praetorian-inc/nebula/pkg/types"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "nebula",
	Short: "Nebula is a CLI tool for testing the offensive security of cloud services.",
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.nebula.yaml)")
	rootCmd.PersistentFlags().StringP(options.OutputOpt.Name, options.OutputOpt.Short, options.OutputOpt.Value, options.OutputOpt.Description)
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".nebula" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".nebula")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}

func options2Flag(options []*types.Option, common []*types.Option, cmd *cobra.Command) {
	for _, option := range options {
		option2Flag(option, cmd)
	}

	for _, option := range common {
		option2Flag(option, cmd)
	}
}

func option2Flag(option *types.Option, cmd *cobra.Command) {
	switch types.OptionType(option.Type) {
	case types.String:
		cmd.Flags().StringP(option.Name, option.Short, option.Value, option.Description)
	case types.Bool:
		value, _ := strconv.ParseBool(option.Value) // Convert string to bool
		cmd.Flags().BoolP(option.Name, option.Short, value, option.Description)
	case types.Int:
		intValue, _ := strconv.Atoi(option.Value) // Convert string to int
		cmd.Flags().IntP(option.Name, option.Short, intValue, option.Description)
	}

	if option.Required {
		cmd.MarkFlagRequired(option.Name)
	}

}

func getOpts(cmd *cobra.Command, required []*types.Option, common []*types.Option) []*types.Option {
	opts := getGlobalOpts(cmd)

	// Process required options
	opts = append(opts, getOptsFromCmd(cmd, required)...)
	err := types.ValidateOptions(opts, required)
	if err != nil {
		log.Default().Println(err)
		os.Exit(1)
	}

	// Process common options
	opts = append(opts, getOptsFromCmd(cmd, common)...)
	err = types.ValidateOptions(opts, common)
	if err != nil {
		log.Default().Println(err)
		os.Exit(1)
	}

	return opts
}

func getGlobalOpts(cmd *cobra.Command) []*types.Option {
	opts := []*types.Option{}
	output := options.OutputOpt
	output.Value, _ = cmd.Flags().GetString(output.Name)
	opts = append(opts, &output)

	return opts
}

func getOptsFromCmd(cmd *cobra.Command, required []*types.Option) []*types.Option {
	opts := []*types.Option{}
	for _, opt := range required {
		switch types.OptionType(opt.Type) {
		case types.String:
			opt.Value, _ = cmd.Flags().GetString(opt.Name)
		case types.Bool:
			value, _ := cmd.Flags().GetBool(opt.Name)
			opt.Value = strconv.FormatBool(value)
		case types.Int:
			value, _ := cmd.Flags().GetInt(opt.Name)
			opt.Value = strconv.Itoa(value)
		}
		opts = append(opts, opt)
	}
	return opts
}

func runModule[In, Out any](ctx context.Context, metadata modules.Metadata, opts []*types.Option, ouputProviders types.OutputProviders, factory stages.StageFactory[In, Out]) {
	in, chain, err := factory(opts)
	if err != nil {
		panic(err)
	}

	wg := new(sync.WaitGroup)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for result := range chain(ctx, opts, in) {
			for _, outputProvider := range ouputProviders {
				wg.Add(1)
				go func(outputProvider types.OutputProvider, result types.Result) {
					err := outputProvider.Write(result)

					if err != nil {
						log.Default().Println(err)
					}
					wg.Done()
				}(outputProvider(opts), types.NewResult(metadata.Platform, metadata.Id, result))
			}
		}
	}()
	// for result := range output {
	// 	logs.ConsoleLogger().Info(fmt.Sprintf("%v", result))
	// }
	wg.Wait()
}
