package extraction

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

func TestExtract_DispatchesToRegistered(t *testing.T) {
	extractorsByType = map[string][]registeredExtractor{}

	var gotResource output.AzureResource
	mustRegister("Microsoft.Compute/virtualMachines", "test", func(_ extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
		gotResource = r
		out.Send(output.ScanInput{Label: "test-label"})
		return nil
	})

	e := NewAzureExtractor(nil, "critical")
	r := output.AzureResource{ResourceType: "Microsoft.Compute/virtualMachines", ResourceID: "test-id"}

	results := pipeline.New[output.ScanInput]()

	// Consume in a goroutine so Send doesn't block
	done := make(chan struct{})
	var collected []output.ScanInput
	go func() {
		defer close(done)
		for item := range results.Range() {
			collected = append(collected, item)
		}
	}()

	err := e.Extract(r, results)
	results.Close()
	<-done

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotResource.ResourceID != "test-id" {
		t.Errorf("expected resource test-id, got %s", gotResource.ResourceID)
	}
	if len(collected) != 1 || collected[0].Label != "test-label" {
		t.Errorf("unexpected collected results: %v", collected)
	}
}

func TestExtract_NoExtractorReturnsError(t *testing.T) {
	extractorsByType = map[string][]registeredExtractor{}

	e := NewAzureExtractor(nil, "critical")
	r := output.AzureResource{ResourceType: "Unknown/Type"}

	results := pipeline.New[output.ScanInput]()
	go func() {
		for range results.Range() {
		}
	}()

	err := e.Extract(r, results)
	results.Close()
	if err == nil {
		t.Error("expected error for unknown type")
	}
}
