package plugin

import "context"

// Processor represents a single processing step
// This is used for modules that need to compose multiple operations
type Processor interface {
	Process(ctx context.Context, input any) ([]any, error)
}

// ProcessorFunc is a function adapter for Processor interface
type ProcessorFunc func(ctx context.Context, input any) ([]any, error)

// Process implements the Processor interface
func (f ProcessorFunc) Process(ctx context.Context, input any) ([]any, error) {
	return f(ctx, input)
}

// Pipeline chains multiple processors together
// This replaces the Janus chain.Link composition pattern
type Pipeline struct {
	processors []Processor
}

// NewPipeline creates a new pipeline with the given processors
func NewPipeline(processors ...Processor) *Pipeline {
	return &Pipeline{processors: processors}
}

// Execute runs all processors in sequence, feeding outputs to inputs
func (p *Pipeline) Execute(ctx context.Context, inputs []any) ([]any, error) {
	current := inputs
	for _, proc := range p.processors {
		var next []any
		for _, input := range current {
			results, err := proc.Process(ctx, input)
			if err != nil {
				return nil, err
			}
			next = append(next, results...)
		}
		current = next
	}
	return current, nil
}
