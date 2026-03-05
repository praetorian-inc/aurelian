package extraction

import "testing"

func TestParseWebAppResourceID(t *testing.T) {
	id := "/subscriptions/sub-1/resourceGroups/my-rg/providers/Microsoft.Web/sites/my-app"
	rg, name, err := parseWebAppResourceID(id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rg != "my-rg" {
		t.Errorf("expected rg my-rg, got %s", rg)
	}
	if name != "my-app" {
		t.Errorf("expected name my-app, got %s", name)
	}
}

func TestParseWebAppResourceID_Invalid(t *testing.T) {
	_, _, err := parseWebAppResourceID("/invalid/path")
	if err == nil {
		t.Error("expected error for invalid resource ID")
	}
}
