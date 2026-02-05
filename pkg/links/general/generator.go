package general

import (
	"context"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

// GeneratorLink is a simple link that generates a single trigger value
// to start a pipeline that doesn't require external input
type GeneratorLink struct {
	*plugin.BaseLink
}

func NewGeneratorLink(args map[string]any) *GeneratorLink {
	return &GeneratorLink{
		BaseLink: plugin.NewBaseLink("generator", args),
	}
}

func (l *GeneratorLink) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		{
			Name:        "trigger-value",
			Description: "Value to send to trigger the pipeline",
			Required:    false,
			Type:        "string",
			Default:     "trigger",
		},
	}
}

func (l *GeneratorLink) Process(ctx context.Context, input any) ([]any, error) {
	// This link ignores input and generates a trigger value
	triggerValue := l.ArgString("trigger-value", "trigger")
	return []any{triggerValue}, nil
}