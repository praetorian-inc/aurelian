package analyze

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/praetorian-inc/aurelian/pkg/m365/benchmark"
	"github.com/praetorian-inc/aurelian/pkg/m365/checks"
	"github.com/praetorian-inc/aurelian/pkg/m365/databag"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	m365templates "github.com/praetorian-inc/aurelian/pkg/templates/m365"
)

// buildComplianceMap builds a full CIS v6.0 compliance map from check results.
// It cross-references the complete benchmark registry against registered check
// functions and actual results to produce PASS/FAIL/NOT TESTED for every control.
func buildComplianceMap(bag *databag.M365DataBag, checkResults map[string]*checks.CheckResult) output.M365ComplianceMap {
	controlRegistry := benchmark.CISV6Controls
	registeredChecks := checks.RegisteredIDs()
	registeredSet := make(map[string]bool, len(registeredChecks))
	for _, id := range registeredChecks {
		registeredSet[id] = true
	}

	var m output.M365ComplianceMap
	m.TenantID = bag.TenantID
	m.TenantDomain = bag.TenantDomain
	m.Benchmark = "CIS Microsoft 365 Foundations Benchmark v6.0.0"
	m.TotalControls = len(controlRegistry)

	for _, ctrl := range controlRegistry {
		entry := output.M365ComplianceEntry{
			CISID:   ctrl.ID,
			Title:   ctrl.Title,
			Level:   ctrl.Level,
			Service: ctrl.Service,
		}

		if !registeredSet[ctrl.ID] {
			// No check function registered for this control
			entry.Status = output.ComplianceNotTested
			m.NotTested++
		} else if result, ok := checkResults[ctrl.ID]; ok {
			// Check was executed
			if result.Passed {
				entry.Status = output.CompliancePass
				entry.Message = result.Message
				m.Passed++
			} else {
				entry.Status = output.ComplianceFail
				entry.Message = result.Message
				m.Failed++
			}
			m.Tested++
		} else {
			// Check is registered but wasn't executed (filtered out or skipped)
			entry.Status = output.ComplianceNotTested
			m.NotTested++
		}

		m.Entries = append(m.Entries, entry)
	}

	return m
}

// emitRisk converts a failed check result into an AurelianRisk and sends it to the output pipeline.
func emitRisk(def *m365templates.M365CheckTemplate, result *checks.CheckResult, bag *databag.M365DataBag, out *pipeline.P[model.AurelianModel]) {
	resourceID := result.ResourceID
	if resourceID == "" {
		resourceID = bag.TenantID
	}

	ctx := M365CheckContext{
		CISID:        def.ID,
		CISTitle:     def.Title,
		Service:      def.Service,
		Level:        def.Level,
		Profile:      def.Profile,
		Execution:    def.Execution,
		TenantID:     bag.TenantID,
		TenantDomain: bag.TenantDomain,
		Evidence:     result.Evidence,
		Message:      result.Message,
		Remediation:  def.Remediation,
		Rationale:    def.Rationale,
		References:   def.References,
		Guard:        def.Guard,
	}

	contextJSON, err := json.Marshal(ctx)
	if err != nil {
		contextJSON = []byte("{}")
	}

	out.Send(output.AurelianRisk{
		Name:               def.Guard.FindingSlug,
		Severity:           output.NormalizeSeverity(def.Severity),
		ImpactedResourceID: "m365://" + bag.TenantDomain + "/" + resourceID,
		DeduplicationID:    "m365-cis-" + def.ID + "-" + bag.TenantID,
		Context:            contextJSON,
	})
}

// evaluateChecks evaluates all check definitions synchronously and returns a map of all results.
// Failed checks are also emitted as AurelianRisk models to the output pipeline.
func evaluateChecks(
	ctx context.Context,
	cfg plugin.Config,
	bag *databag.M365DataBag,
	checkDefs []*m365templates.M365CheckTemplate,
	out *pipeline.P[model.AurelianModel],
) map[string]*checks.CheckResult {
	allResults := make(map[string]*checks.CheckResult)

	for _, def := range checkDefs {
		fn, ok := checks.Get(def.ID)
		if !ok {
			slog.Warn("no check function registered", "cis_id", def.ID)
			continue
		}

		result, err := fn(ctx, bag)
		if err != nil {
			slog.Warn("check failed with error", "cis_id", def.ID, "error", err)
			continue
		}
		allResults[def.ID] = result

		if result.Passed {
			cfg.Success("[PASS] %s: %s", def.ID, def.Title)
		} else {
			cfg.Fail("[FAIL] %s: %s - %s", def.ID, def.Title, result.Message)
			emitRisk(def, result, bag, out)
		}
	}

	return allResults
}
