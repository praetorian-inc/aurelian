package extraction

import "testing"

func TestParseVMResourceID(t *testing.T) {
	id := "/subscriptions/sub-1/resourceGroups/my-rg/providers/Microsoft.Compute/virtualMachines/my-vm"
	rg, name, err := parseVMResourceID(id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rg != "my-rg" {
		t.Errorf("expected rg my-rg, got %s", rg)
	}
	if name != "my-vm" {
		t.Errorf("expected name my-vm, got %s", name)
	}
}

func TestParseVMResourceID_Invalid(t *testing.T) {
	_, _, err := parseVMResourceID("/invalid/path")
	if err == nil {
		t.Error("expected error for invalid resource ID")
	}
}
