package outputters

import (
	"fmt"

	"github.com/praetorian-inc/aurelian/internal/message"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

// URLConsoleOutputter outputs URLs to the console with formatting
type URLConsoleOutputter struct {
	cfg  plugin.Config
	urls []string
}

func NewURLConsoleOutputter() *URLConsoleOutputter {
	return &URLConsoleOutputter{
		urls: make([]string, 0),
	}
}

func (o *URLConsoleOutputter) Initialize(cfg plugin.Config) error {
	o.cfg = cfg
	return nil
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