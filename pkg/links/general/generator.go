package general

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
)

// GeneratorLink is a simple link that generates a single trigger value
// to start a pipeline that doesn't require external input
type GeneratorLink struct {
	*chain.Base
}

func NewGeneratorLink(configs ...cfg.Config) chain.Link {
	l := &GeneratorLink{}
	l.Base = chain.NewBase(l, configs...)
	return l
}

func (l *GeneratorLink) Params() []cfg.Param {
	return []cfg.Param{
		cfg.NewParam[string]("trigger-value", "Value to send to trigger the pipeline").WithDefault("trigger"),
	}
}

func (l *GeneratorLink) Process(input any) error {
	// This link ignores input and generates a trigger value
	triggerValue, _ := cfg.As[string](l.Arg("trigger-value"))
	l.Send(triggerValue)
	return nil
}