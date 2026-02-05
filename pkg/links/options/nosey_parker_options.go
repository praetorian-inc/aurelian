package options

import (
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

var NoseyParkerPathOpt = types.Option{
	Name:        "np-path",
	Description: "path to Nosey Parker",
	Required:    false,
	Type:        types.String,
	Value:       "noseyparker",
}

var NoseyParkerArgsOpt = types.Option{
	Name:        "np-args",
	Description: "custom args to pass to Nosey Parker",
	Required:    false,
	Type:        types.String,
	Value:       "",
}

var NoseyParkerOutputOpt = types.Option{
	Name:        "np-output",
	Description: "output directory for Nosey Parker",
	Required:    false,
	Type:        types.String,
	Value:       "datastore.np",
}

var NoseyParkerScanOpt = types.Option{
	Name:        "np-scan",
	Description: "scan for secrets using Nosey Parker",
	Required:    false,
	Type:        types.Bool,
	Value:       "true",
}

// Janus-compatible NoseyParker parameters
func NoseyParkerPath() plugin.Parameter {
	return plugin.NewParam[string]("nosey-parker-path", "Path to NoseyParker executable",
		plugin.WithDefault("noseyparker"),
	)
}

func NoseyParkerOutput() plugin.Parameter {
	return plugin.NewParam[string]("nosey-parker-output", "Output directory for NoseyParker datastore",
		plugin.WithDefault("datastore.np"),
	)
}

func NoseyParkerArgs() plugin.Parameter {
	return plugin.NewParam[string]("nosey-parker-args", "Custom arguments to pass to NoseyParker",
		plugin.WithDefault(""),
	)
}
