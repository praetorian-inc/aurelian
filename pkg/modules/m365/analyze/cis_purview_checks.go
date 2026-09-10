package analyze

import (
	"context"
	"fmt"

	"github.com/praetorian-inc/aurelian/pkg/m365/checks"
	"github.com/praetorian-inc/aurelian/pkg/m365/databag"
)

func init() {
	checks.Register("3.1.1", checkUnifiedAuditLogEnabled)
	checks.Register("3.2.2", checkDLPForTeams)
	checks.Register("3.3.1", checkSensitivityLabelsPublished)
}

// 3.1.1: Ensure Microsoft 365 audit log search is enabled
func checkUnifiedAuditLogEnabled(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.PurviewAuditConfig == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Purview audit configuration not available",
		}, nil
	}

	if bag.PurviewAuditConfig.UnifiedAuditLogEnabled {
		return &checks.CheckResult{
			Passed:  true,
			Message: "Unified audit log search is enabled",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Unified audit log search is not enabled",
		Evidence: map[string]any{
			"unifiedAuditLogEnabled": bag.PurviewAuditConfig.UnifiedAuditLogEnabled,
		},
	}, nil
}

// 3.2.2: Ensure DLP policies are enabled for Microsoft Teams
func checkDLPForTeams(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if len(bag.DLPPolicies) == 0 {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "No DLP policies found",
		}, nil
	}

	for _, policy := range bag.DLPPolicies {
		if policy.IsEnabled && policy.TeamsEnabled {
			return &checks.CheckResult{
				Passed:  true,
				Message: "DLP policy is enabled for Microsoft Teams",
			}, nil
		}
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "No DLP policy is enabled for Microsoft Teams",
		Evidence: map[string]any{
			"policies_checked": len(bag.DLPPolicies),
		},
	}, nil
}

// 3.3.1: Ensure Information Protection sensitivity labels are published
func checkSensitivityLabelsPublished(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if len(bag.SensitivityLabels) == 0 {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "No sensitivity labels found",
		}, nil
	}

	publishedCount := 0
	for _, label := range bag.SensitivityLabels {
		if label.Published {
			publishedCount++
		}
	}

	if publishedCount > 0 {
		return &checks.CheckResult{
			Passed:  true,
			Message: fmt.Sprintf("%d sensitivity label(s) are published", publishedCount),
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "No sensitivity labels are published",
		Evidence: map[string]any{
			"total_labels": len(bag.SensitivityLabels),
		},
	}, nil
}
