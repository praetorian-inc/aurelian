package extraction

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

// extractContext holds per-resource Azure credential and extraction settings.
type extractContext struct {
	Context          context.Context
	Cred             azcore.TokenCredential
	ScanMode         string // "critical" or "all" — used by storage blob extractor
	MaxCosmosDocSize int    // max individual Cosmos document size in bytes; 0 uses defaultMaxCosmosDocSize
	MaxCosmosDocScan int    // max total documents to scan per container; 0 means unlimited
}

// extractorFunc is the signature for per-resource extraction functions.
type extractorFunc func(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error

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
