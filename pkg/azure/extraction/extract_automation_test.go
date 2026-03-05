package extraction

import "testing"

func TestParseAutomationAccountResourceID(t *testing.T) {
	id := "/subscriptions/sub-1/resourceGroups/my-rg/providers/Microsoft.Automation/automationAccounts/my-acct"
	rg, name, err := parseAutomationAccountResourceID(id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rg != "my-rg" {
		t.Errorf("expected rg my-rg, got %s", rg)
	}
	if name != "my-acct" {
		t.Errorf("expected name my-acct, got %s", name)
	}
}

func TestParseAutomationAccountResourceID_Invalid(t *testing.T) {
	_, _, err := parseAutomationAccountResourceID("/invalid")
	if err == nil {
		t.Error("expected error")
	}
}
