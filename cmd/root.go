package cmd

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"
	"strconv"
	"sync"

	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/internal/message"
	"github.com/praetorian-inc/nebula/modules"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/stages"
	"github.com/praetorian-inc/nebula/pkg/types"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile      string
	quietFlag    bool
	noColorFlag  bool
	silentFlag   bool
	logLevelFlag string
)

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
	rootCmd.PersistentFlags().StringVar(&logLevelFlag, options.LogLevelOpt.Name, options.LogLevelOpt.Value, "Log level (debug, info, warn, error)")
	//rootCmd.PersistentFlags().StringP(options.LogLevelOpt.Name, options.LogLevelOpt.Short, options.LogLevelOpt.Value, options.LogLevelOpt.Description)
	rootCmd.PersistentFlags().StringP(options.OutputOpt.Name, options.OutputOpt.Short, options.OutputOpt.Value, options.OutputOpt.Description)
	rootCmd.PersistentFlags().BoolVar(&quietFlag, "quiet", false, "Suppress user messages")
	rootCmd.PersistentFlags().BoolVar(&noColorFlag, "no-color", false, "Disable colored output")
	rootCmd.PersistentFlags().BoolVar(&silentFlag, "silent", false, "Suppress all messages except critical errors")
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
	viper.SetEnvPrefix("NEBULA")

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}

	logs.ConfigureDefaults(logLevelFlag)
	message.SetQuiet(quietFlag)
	message.SetNoColor(noColorFlag)
	message.SetSilent(silentFlag)
	message.Banner()
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

// Helper function to convert option names to viper config keys
// func getConfigKey(optionName string) string {
// 	// Convert option names like "aws-region" to "aws.region"
// 	parts := strings.Split(optionName, "-")
// 	if len(parts) > 1 {
// 		return fmt.Sprintf("%s.%s", parts[0], strings.Join(parts[1:], "."))
// 	}
// 	return optionName
// }

func getOpts(cmd *cobra.Command, required []*types.Option, common []*types.Option) []*types.Option {
	opts := getGlobalOpts(cmd)

	// Process required options
	opts = append(opts, getOptsFromCmd(cmd, required)...)
	err := options.ValidateOptions(opts, required)
	if err != nil {
		log.Default().Println(err)
		os.Exit(1)
	}

	// Process common options
	opts = append(opts, getOptsFromCmd(cmd, common)...)
	err = options.ValidateOptions(opts, common)
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
	ctx = context.WithValue(ctx, "metadata", metadata)
	logger := logs.NewModuleLogger(ctx, opts)
	message.Section(metadata.Name)
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
				go func(outputProvider types.OutputProvider, result Out) {
					var finalResult types.Result

					// Check if result is already of type Result
					if r, ok := any(result).(types.Result); ok {
						finalResult = r
						logger.Debug("Final result is of type result, do not need to create new result")
					} else {
						finalResult = types.NewResult(metadata.Platform, metadata.Id, result)
					}

					err := outputProvider.Write(finalResult)
					if err != nil {
						logger.Error("Error writing output", slog.String("error", err.Error()), slog.String("output-provider", fmt.Sprintf("%T", outputProvider)))
					}
					wg.Done()
				}(outputProvider(opts), result)
			}
		}
	}()
	wg.Wait()
}
