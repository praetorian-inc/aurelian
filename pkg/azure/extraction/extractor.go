package extraction

import (
	"context"
	"log/slog"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"

	"github.com/praetorian-inc/aurelian/pkg/azure/azurecloud"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

// AzureExtractor extracts scannable content from Azure resources.
type AzureExtractor struct {
	cred             azcore.TokenCredential
	env              azurecloud.Environment
	MaxCosmosDocSize int // 0 uses defaultMaxCosmosDocSize (1 MB)
	MaxCosmosDocScan int // 0 uses defaultMaxCosmosDocScan (50)
}

// NewAzureExtractor creates an extractor with shared Azure credentials.
func NewAzureExtractor(cred azcore.TokenCredential, env azurecloud.Environment) *AzureExtractor {
	if skipped := unsupportedExtractors(env); len(skipped) > 0 {
		slog.Warn("extractors unavailable in selected cloud; results are partial", "cloud", env.Name, "extractors", skipped)
	}
	return &AzureExtractor{
		cred: cred,
		env:  env,
	}
}

// Extract is a pipeline-compatible method that dispatches by resource type.
func (e *AzureExtractor) Extract(r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	normalizedType := strings.ToLower(r.ResourceType)
	extractors := getExtractors(normalizedType)
	if len(extractors) == 0 {
		slog.Debug("no extractor registered for resource type, skipping",
			"type", r.ResourceType, "resource", r.ResourceID)
		return nil
	}

	ctx := extractContext{
		Context:          context.Background(),
		Cred:             e.cred,
		Env:              e.env,
		MaxCosmosDocSize: e.MaxCosmosDocSize,
		MaxCosmosDocScan: e.MaxCosmosDocScan,
	}

	for _, ext := range extractors {
		if !e.env.Supports(ext.Clouds) {
			slog.Debug("extractor not supported in selected cloud, skipping", "name", ext.Name, "cloud", e.env.Name, "resource", r.ResourceID)
			continue
		}
		if err := ext.Fn(ctx, r, out); err != nil {
			slog.Warn("azure extractor failed", "name", ext.Name, "type", r.ResourceType, "resource", r.ResourceID, "error", err)
		}
	}

	// Cross-cutting: scan tags on all resources (zero API cost, tags from ARG).
	if err := extractTags(ctx, r, out); err != nil {
		slog.Warn("tag extraction failed", "resource", r.ResourceID, "error", err)
	}

	return nil
}
