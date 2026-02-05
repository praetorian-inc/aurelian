package orchestrator

import "github.com/praetorian-inc/aurelian/pkg/dispatcher"

// Option configures the AWS secrets orchestrator
type Option func(*config)

type config struct {
	processOpts      *dispatcher.ProcessOptions
	concurrencyLimit int
}

// WithProcessOptions sets the processing options for all processors
func WithProcessOptions(opts *dispatcher.ProcessOptions) Option {
	return func(c *config) {
		c.processOpts = opts
	}
}

// WithConcurrencyLimit sets the maximum number of concurrent resource processors.
// Default is 25 if not specified.
func WithConcurrencyLimit(limit int) Option {
	return func(c *config) {
		if limit > 0 {
			c.concurrencyLimit = limit
		}
	}
}

// defaultConfig returns the default orchestrator configuration
func defaultConfig() *config {
	return &config{
		processOpts:      dispatcher.DefaultProcessOptions(),
		concurrencyLimit: 25,
	}
}

// applyOptions applies functional options to the config
func applyOptions(opts []Option) *config {
	cfg := defaultConfig()
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg
}
