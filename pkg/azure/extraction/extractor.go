package extraction

import (
	"context"
	"log/slog"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

// AzureExtractor extracts scannable content from Azure resources.
type AzureExtractor struct {
	cred azcore.TokenCredential
}

// NewAzureExtractor creates an extractor with shared Azure credentials.
func NewAzureExtractor(cred azcore.TokenCredential) *AzureExtractor {
	return &AzureExtractor{
		cred: cred,
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
		Context: context.Background(),
		Cred:    e.cred,
	}

	for _, ext := range extractors {
		if err := ext.Fn(ctx, r, out); err != nil {
			slog.Warn("azure extractor failed", "name", ext.Name, "type", r.ResourceType, "resource", r.ResourceID, "error", err)
		}
	}
	return nil
}
