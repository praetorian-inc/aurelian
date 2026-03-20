package extraction

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

func TestExtractTags_NonEmpty(t *testing.T) {
	r := output.AzureResource{
		ResourceID:     "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1",
		ResourceType:   "microsoft.compute/virtualmachines",
		SubscriptionID: "sub1",
		Location:       "eastus",
		Tags:           map[string]string{"password": "hunter2", "env": "prod"},
	}

	out := pipeline.New[output.ScanInput]()
	go func() {
		defer out.Close()
		_ = extractTags(extractContext{}, r, out)
	}()

	results, _ := out.Collect()
	if len(results) != 1 {
		t.Fatalf("expected 1 ScanInput, got %d", len(results))
	}
	if results[0].Label != "Tags" {
		t.Errorf("expected label 'Tags', got %q", results[0].Label)
	}
	if results[0].ResourceID != r.ResourceID {
		t.Errorf("expected ResourceID %q, got %q", r.ResourceID, results[0].ResourceID)
	}
}

func TestExtractTags_Empty(t *testing.T) {
	r := output.AzureResource{
		ResourceID: "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1",
		Tags:       nil,
	}

	out := pipeline.New[output.ScanInput]()
	go func() {
		defer out.Close()
		_ = extractTags(extractContext{}, r, out)
	}()

	results, _ := out.Collect()
	if len(results) != 0 {
		t.Fatalf("expected 0 ScanInputs for nil tags, got %d", len(results))
	}
}
