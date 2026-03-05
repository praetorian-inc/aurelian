package output

import "testing"

func TestScanInputFromAzureResource(t *testing.T) {
	r := AzureResource{
		ResourceID:     "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/myvm",
		ResourceType:   "Microsoft.Compute/virtualMachines",
		SubscriptionID: "sub-1",
		Location:       "eastus",
	}
	content := []byte("secret=abc123")

	si := ScanInputFromAzureResource(r, "UserData", content)

	if si.ResourceID != r.ResourceID {
		t.Errorf("ResourceID mismatch: got %s", si.ResourceID)
	}
	if si.ResourceType != r.ResourceType {
		t.Errorf("ResourceType mismatch: got %s", si.ResourceType)
	}
	if si.Region != "eastus" {
		t.Errorf("Region mismatch: got %s", si.Region)
	}
	if si.AccountID != "sub-1" {
		t.Errorf("AccountID mismatch: got %s", si.AccountID)
	}
	if si.Label != "UserData" {
		t.Errorf("Label mismatch: got %s", si.Label)
	}
	if string(si.Content) != "secret=abc123" {
		t.Errorf("Content mismatch: got %s", string(si.Content))
	}
}
