package options

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/types"
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
func NoseyParkerPath() cfg.Param {
	return cfg.NewParam[string]("nosey-parker-path", "Path to NoseyParker executable").
		WithDefault("noseyparker")
}

func NoseyParkerOutput() cfg.Param {
	return cfg.NewParam[string]("nosey-parker-output", "Output directory for NoseyParker datastore").
		WithDefault("datastore.np")
}

func NoseyParkerArgs() cfg.Param {
	return cfg.NewParam[string]("nosey-parker-args", "Custom arguments to pass to NoseyParker").
		WithDefault("")
}
