package analyze

import (
	"context"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/m365/databag"
)

// ---------------------------------------------------------------------------
// 3.1.1 - checkUnifiedAuditLogEnabled
// ---------------------------------------------------------------------------

func TestCheckUnifiedAuditLogEnabled_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		PurviewAuditConfig: &databag.PurviewAuditConfig{
			UnifiedAuditLogEnabled: true,
		},
	}

	result, err := checkUnifiedAuditLogEnabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckUnifiedAuditLogEnabled_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		PurviewAuditConfig: &databag.PurviewAuditConfig{
			UnifiedAuditLogEnabled: false,
		},
	}

	result, err := checkUnifiedAuditLogEnabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when unified audit log is disabled")
	}
}

func TestCheckUnifiedAuditLogEnabled_Fail_Nil(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkUnifiedAuditLogEnabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with nil Purview audit config")
	}
}

// ---------------------------------------------------------------------------
// Edge-case and negative tests
// ---------------------------------------------------------------------------

func TestCheckUnifiedAuditLog_EmptyStruct(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID:           "test-tenant",
		PurviewAuditConfig: &databag.PurviewAuditConfig{},
	}

	result, err := checkUnifiedAuditLogEnabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with PurviewAuditConfig with all defaults (false)")
	}
}
