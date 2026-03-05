package extraction

import "testing"

func TestParseResourceID_AllTypes(t *testing.T) {
	tests := []struct {
		name        string
		id          string
		rgKey       string
		resourceKey string
		wantRG      string
		wantName    string
		wantErr     bool
	}{
		{
			name:        "VM",
			id:          "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/virtualMachines/vm-1",
			rgKey:       "resourceGroups",
			resourceKey: "virtualMachines",
			wantRG:      "rg-1",
			wantName:    "vm-1",
		},
		{
			name:        "Web App",
			id:          "/subscriptions/sub-1/resourceGroups/rg-2/providers/Microsoft.Web/sites/app-1",
			rgKey:       "resourceGroups",
			resourceKey: "sites",
			wantRG:      "rg-2",
			wantName:    "app-1",
		},
		{
			name:        "Automation Account",
			id:          "/subscriptions/sub-1/resourceGroups/rg-3/providers/Microsoft.Automation/automationAccounts/acct-1",
			rgKey:       "resourceGroups",
			resourceKey: "automationAccounts",
			wantRG:      "rg-3",
			wantName:    "acct-1",
		},
		{
			name:        "Storage Account",
			id:          "/subscriptions/sub-1/resourceGroups/rg-4/providers/Microsoft.Storage/storageAccounts/store1",
			rgKey:       "resourceGroups",
			resourceKey: "storageAccounts",
			wantRG:      "rg-4",
			wantName:    "store1",
		},
		{
			name:        "Missing resource group",
			id:          "/subscriptions/sub-1/providers/Microsoft.Compute/virtualMachines/vm-1",
			rgKey:       "resourceGroups",
			resourceKey: "virtualMachines",
			wantErr:     true,
		},
		{
			name:        "Empty string",
			id:          "",
			rgKey:       "resourceGroups",
			resourceKey: "virtualMachines",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rg, name, err := parseResourceID(tt.id, tt.rgKey, tt.resourceKey)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if rg != tt.wantRG {
				t.Errorf("rg: got %s, want %s", rg, tt.wantRG)
			}
			if name != tt.wantName {
				t.Errorf("name: got %s, want %s", name, tt.wantName)
			}
		})
	}
}
