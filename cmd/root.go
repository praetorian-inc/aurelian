package cmd

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"

	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/modules"
	o "github.com/praetorian-inc/nebula/modules/options"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "nebula",
	Short: "Nebula is a CLI tool for offensive security testing cloud services.",
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.nebula.yaml)")
	rootCmd.PersistentFlags().StringP(o.OutputOpt.Name, o.OutputOpt.Short, o.OutputOpt.Value, o.OutputOpt.Description)
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

func options2Flag(options []*o.Option, common []*o.Option, cmd *cobra.Command) {
	for _, option := range options {
		option2Flag(option, cmd)
	}

	for _, option := range common {
		option2Flag(option, cmd)
	}
}

func option2Flag(option *o.Option, cmd *cobra.Command) {
	switch o.OptionType(option.Type) {
	case o.String:
		cmd.Flags().StringP(option.Name, option.Short, option.Value, option.Description)
	case o.Bool:
		value, _ := strconv.ParseBool(option.Value) // Convert string to bool
		cmd.Flags().BoolP(option.Name, option.Short, value, option.Description)
	case o.Int:
		intValue, _ := strconv.Atoi(option.Value) // Convert string to int
		cmd.Flags().IntP(option.Name, option.Short, intValue, option.Description)
	}

	if option.Required {
		cmd.MarkFlagRequired(option.Name)
	}

}

func getOpts(cmd *cobra.Command, required []*o.Option, common []*o.Option) []*o.Option {
	opts := getGlobalOpts(cmd)

	// Process required options
	opts = append(opts, getOptsFromCmd(cmd, required)...)
	err := o.ValidateOptions(opts, required)
	if err != nil {
		log.Default().Println(err)
		os.Exit(1)
	}

	// Process common options
	opts = append(opts, getOptsFromCmd(cmd, common)...)
	err = o.ValidateOptions(opts, common)
	if err != nil {
		log.Default().Println(err)
		os.Exit(1)
	}

	return opts
}

func getGlobalOpts(cmd *cobra.Command) []*o.Option {
	opts := []*o.Option{}
	output := o.OutputOpt
	output.Value, _ = cmd.Flags().GetString(output.Name)
	opts = append(opts, &output)

	return opts
}

func getOptsFromCmd(cmd *cobra.Command, required []*o.Option) []*o.Option {
	opts := []*o.Option{}
	for _, opt := range required {
		switch o.OptionType(opt.Type) {
		case o.String:
			opt.Value, _ = cmd.Flags().GetString(opt.Name)
		case o.Bool:
			value, _ := cmd.Flags().GetBool(opt.Name)
			opt.Value = strconv.FormatBool(value)
		case o.Int:
			value, _ := cmd.Flags().GetInt(opt.Name)
			opt.Value = strconv.Itoa(value)
		}
		opts = append(opts, opt)
	}
	return opts
}

func runModule(module modules.Module, meta modules.Metadata, options []*o.Option, run modules.Run) {
	wg := new(sync.WaitGroup)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for result := range run.Data {
			for _, outputProvider := range module.GetOutputProviders() {
				wg.Add(1)
				go func(outputProvider modules.OutputProvider, result modules.Result) {
					err := outputProvider.Write(result)

					if err != nil {
						log.Default().Println(err)
					}
					wg.Done()
				}(outputProvider, result)
			}
		}
	}()

	helpers.PrintMessage(meta.Name)
	err := module.Invoke()
	if err != nil {
		log.Default().Println(err)
	}
	wg.Wait()
}
