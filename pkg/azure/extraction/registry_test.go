package extraction

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

func TestMustRegister_And_GetExtractors(t *testing.T) {
	extractorsByType = map[string][]registeredExtractor{}

	mustRegister("Microsoft.Compute/virtualMachines", "test-vm", func(_ extractContext, _ output.AzureResource, _ *pipeline.P[output.ScanInput]) error {
		return nil
	})

	extractors := getExtractors("Microsoft.Compute/virtualMachines")
	if len(extractors) != 1 {
		t.Fatalf("expected 1 extractor, got %d", len(extractors))
	}
	if extractors[0].Name != "test-vm" {
		t.Errorf("expected name test-vm, got %s", extractors[0].Name)
	}
}

func TestGetExtractors_UnknownType(t *testing.T) {
	extractorsByType = map[string][]registeredExtractor{}

	extractors := getExtractors("Unknown/Type")
	if len(extractors) != 0 {
		t.Errorf("expected 0 extractors, got %d", len(extractors))
	}
}

func TestMustRegister_DuplicatePanics(t *testing.T) {
	extractorsByType = map[string][]registeredExtractor{}

	mustRegister("Microsoft.Compute/virtualMachines", "test-vm", func(_ extractContext, _ output.AzureResource, _ *pipeline.P[output.ScanInput]) error {
		return nil
	})

	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on duplicate registration")
		}
	}()

	mustRegister("Microsoft.Compute/virtualMachines", "test-vm", func(_ extractContext, _ output.AzureResource, _ *pipeline.P[output.ScanInput]) error {
		return nil
	})
}
