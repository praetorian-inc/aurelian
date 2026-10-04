package analyze

import (
	"context"

	"github.com/praetorian-inc/aurelian/pkg/m365/checks"
	"github.com/praetorian-inc/aurelian/pkg/m365/databag"
)

func init() {
	checks.Register("4.1", checkIntuneDevicesNonCompliant)
	checks.Register("4.2", checkIntunePersonalEnrollmentBlocked)
}

// 4.1: Ensure devices without a compliance policy are marked as not compliant
func checkIntuneDevicesNonCompliant(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.IntuneDeviceCompliance == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Intune device compliance settings not available",
		}, nil
	}

	if bag.IntuneDeviceCompliance.MarkDevicesNonCompliant {
		return &checks.CheckResult{
			Passed:  true,
			Message: "Devices without a compliance policy are marked as not compliant",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Devices without a compliance policy are not marked as not compliant",
		Evidence: map[string]any{
			"markDevicesNonCompliant": bag.IntuneDeviceCompliance.MarkDevicesNonCompliant,
		},
	}, nil
}

// 4.2: Ensure device enrollment for personal devices is blocked by default
func checkIntunePersonalEnrollmentBlocked(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.IntuneEnrollmentRestriction == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Intune enrollment restriction settings not available",
		}, nil
	}

	if bag.IntuneEnrollmentRestriction.PersonalDeviceEnrollmentBlocked {
		return &checks.CheckResult{
			Passed:  true,
			Message: "Personal device enrollment is blocked by default",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Personal device enrollment is not blocked by default",
		Evidence: map[string]any{
			"personalDeviceEnrollmentBlocked": bag.IntuneEnrollmentRestriction.PersonalDeviceEnrollmentBlocked,
		},
	}, nil
}
