package extraction

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

// AzureExtractor extracts scannable content from Azure resources.
type AzureExtractor struct {
	cred     azcore.TokenCredential
	scanMode string
}

// NewAzureExtractor creates an extractor with Azure credentials and scan mode.
func NewAzureExtractor(cred azcore.TokenCredential, scanMode string) *AzureExtractor {
	return &AzureExtractor{
		cred:     cred,
		scanMode: scanMode,
	}
}

// Extract is a pipeline-compatible method that dispatches by resource type.
func (e *AzureExtractor) Extract(r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	extractors := getExtractors(r.ResourceType)
	if len(extractors) == 0 {
		return fmt.Errorf("no extractor registered for resource type %s", r.ResourceType)
	}

	ec := extractContext{
		Context:  context.Background(),
		Cred:     e.cred,
		ScanMode: e.scanMode,
	}

	for _, ext := range extractors {
		if err := ext.Fn(ec, r, out); err != nil {
			slog.Warn("azure extractor failed", "name", ext.Name, "type", r.ResourceType, "resource", r.ResourceID, "error", err)
		}
	}
	return nil
}
