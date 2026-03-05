package extraction

import "testing"

func TestParseStorageAccountResourceID(t *testing.T) {
	id := "/subscriptions/sub-1/resourceGroups/my-rg/providers/Microsoft.Storage/storageAccounts/mystorageacct"
	rg, name, err := parseStorageAccountResourceID(id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rg != "my-rg" {
		t.Errorf("expected rg my-rg, got %s", rg)
	}
	if name != "mystorageacct" {
		t.Errorf("expected name mystorageacct, got %s", name)
	}
}

func TestMatchesCriticalPattern(t *testing.T) {
	tests := []struct {
		name string
		key  string
		want bool
	}{
		{"terraform state", "terraform.tfstate", true},
		{"env file", ".env", true},
		{"credentials", "credentials.json", true},
		{"random file", "readme.md", false},
		{"image", "photo.jpg", false},
		{"ssh key", "id_rsa", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchesCriticalPattern(tt.key); got != tt.want {
				t.Errorf("matchesCriticalPattern(%q) = %v, want %v", tt.key, got, tt.want)
			}
		})
	}
}

func TestShouldSkipExtension(t *testing.T) {
	if !shouldSkipExtension(".zip") {
		t.Error("expected .zip to be skipped")
	}
	if shouldSkipExtension(".json") {
		t.Error("expected .json to not be skipped")
	}
}
