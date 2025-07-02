package options

import (
	"regexp"

	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/types"
)

func WithValue(opt types.Option, value string) *types.Option {
	opt.Value = value
	return &opt
}

var OutputOpt = types.Option{
	Name:        "output",
	Short:       "o",
	Description: "output directory",
	Required:    false,
	Type:        types.String,
	Value:       "nebula-output",
}

var FileNameOpt = types.Option{
	Name:        "file",
	Short:       "f",
	Description: "File name",
	Required:    false,
	Type:        types.String,
	Value:       "",
}

var PathOpt = types.Option{
	Name:        "path",
	Description: "path to the file",
	Required:    true,
	Type:        types.String,
	Value:       "",
}

var DirPathOpt = types.Option{
	Name:        "directory path",
	Short:       "d",
	Description: "path to an input directory",
	Required:    true,
	Type:        types.String,
	Value:       "",
}

var ProviderType = types.Option{
	Name:        "csp",
	Short:       "c",
	Description: "the Cloud Service Provider of context - aws, gcp, or azure",
	Required:    true,
	Type:        types.String,
	Value:       "",
}

var UrlOpt = types.Option{
	Name:        "url",
	Short:       "u",
	Description: "url to the file",
	Required:    true,
	Type:        types.String,
	Value:       "",
}

var PromptOpt = types.Option{
	Name:        "prompt",
	Description: "prompt for input",
	Required:    false,
	Type:        types.String,
	Value:       "",
}

var ModelOpt = types.Option{
	Name:        "model",
	Description: "ollama model",
	Required:    false,
	Type:        types.String,
	Value:       "llama3",
}

var IPOpt = types.Option{
	Name:        "ip",
	Description: "ip address",
	Required:    true,
	Type:        types.String,
	Value:       "",
	ValueFormat: regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$`),
}

var JqFilterOpt = types.Option{
	Name:        "jq",
	Description: "jq filter",
	Required:    false,
	Type:        types.String,
	Value:       "",
}

var ImageOpt = types.Option{
	Name:        "image",
	Short:       "i",
	Description: "docker image",
	Required:    true,
	Type:        types.String,
	Value:       "",
}

var WorkersOpt = types.Option{
	Name:        "workers",
	Short:       "w",
	Description: "number of workers",
	Required:    false,
	Type:        types.Int,
	Value:       "10",
}

var LogLevelOpt = types.Option{
	Name:        "log-level",
	Description: "log level",
	Required:    false,
	Type:        types.String,
	Value:       "warn",
	ValueFormat: regexp.MustCompile("^(debug|info|warn|error)$"),
}

func LogLevel() cfg.Param {
	return cfg.NewParam[string]("log-level", "log level").
		WithDefault("none").
		WithRegex(regexp.MustCompile("^(none|debug|info|warn|error)$"))
}

func AwsCacheLogLevel() cfg.Param {
	return cfg.NewParam[string]("aws-cache-log-level", "Log level for AWS cache operations (debug, info, warn, error, none). Overrides global --log-level for cache logging.").
		WithRegex(regexp.MustCompile("^(none|debug|info|warn|error)$"))
}

func AwsCacheLogFile() cfg.Param {
	return cfg.NewParam[string]("aws-cache-log-file", "File path to redirect AWS cache logs. If not specified, logs will be written to stdout.")
}

func IP() cfg.Param {
	return cfg.NewParam[[]string]("ip", "ip address").
		WithRegex(regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$`)).
		WithShortcode("i").
		AsRequired()

}
