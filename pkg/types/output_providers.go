package types

type OutputProvider interface {
	Write(result Result) error
}

type OutputProviders []func(options []*Option) OutputProvider
