package extraction

import (
	"context"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"google.golang.org/api/option"
)

// extractContext holds per-resource GCP config and extraction settings.
type extractContext struct {
	Context       context.Context
	ClientOptions []option.ClientOption
}

// extractorFunc is the signature for per-resource extraction functions.
type extractorFunc func(ctx extractContext, r output.GCPResource, out *pipeline.P[output.ScanInput]) error

type registeredExtractor struct {
	Name string
	Fn   extractorFunc
}

var extractorsByType = map[string][]registeredExtractor{}

func mustRegister(resourceType, name string, fn extractorFunc) {
	if resourceType == "" {
		panic("resourceType cannot be empty")
	}
	if name == "" {
		panic("name cannot be empty")
	}
	if fn == nil {
		panic("extractor function cannot be nil")
	}
	existing := extractorsByType[resourceType]
	for _, item := range existing {
		if item.Name == name {
			panic("extractor already registered: " + resourceType + "/" + name)
		}
	}
	extractorsByType[resourceType] = append(existing, registeredExtractor{Name: name, Fn: fn})
}

func getExtractors(resourceType string) []registeredExtractor {
	return extractorsByType[resourceType]
}
