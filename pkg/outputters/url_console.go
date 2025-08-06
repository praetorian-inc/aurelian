package outputters

import (
	"fmt"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/message"
)

// URLConsoleOutputter outputs URLs to the console with formatting
type URLConsoleOutputter struct {
	*chain.BaseOutputter
	urls []string
}

func NewURLConsoleOutputter(configs ...cfg.Config) chain.Outputter {
	outputter := &URLConsoleOutputter{
		urls: make([]string, 0),
	}
	outputter.BaseOutputter = chain.NewBaseOutputter(outputter, configs...)
	return outputter
}

func (o *URLConsoleOutputter) Params() []cfg.Param {
	return []cfg.Param{}
}

func (o *URLConsoleOutputter) Output(val any) error {
	if url, ok := val.(string); ok {
		o.urls = append(o.urls, url)
	}
	return nil
}

func (o *URLConsoleOutputter) Complete() error {
	if len(o.urls) == 0 {
		message.Info("No URLs generated")
		return nil
	}

	message.Info("Generated URLs:")
	for i, url := range o.urls {
		fmt.Printf("[%d] %s\n", i+1, url)
	}

	return nil
}