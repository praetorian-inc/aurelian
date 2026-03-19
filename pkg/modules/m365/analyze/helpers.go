package analyze

import (
	"encoding/json"

	"github.com/praetorian-inc/aurelian/pkg/m365/checks"
	"github.com/praetorian-inc/aurelian/pkg/m365/databag"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	m365templates "github.com/praetorian-inc/aurelian/pkg/templates/m365"
)

// M365CheckContext is the structured context emitted with each AurelianRisk.
type M365CheckContext struct {
	CISID        string         `json:"cis_id"`
	CISTitle     string         `json:"cis_title"`
	Service      string         `json:"service"`
	Level        string         `json:"level"`
	Profile      string         `json:"profile"`
	Execution    string         `json:"execution"`
	TenantID     string         `json:"tenant_id"`
	TenantDomain string         `json:"tenant_domain"`
	Evidence     map[string]any `json:"evidence,omitempty"`
	Message      string         `json:"message"`
	Remediation  string         `json:"remediation"`
	Rationale    string         `json:"rationale"`
	References   []string       `json:"references,omitempty"`
	Guard        m365templates.GuardMeta `json:"guard"`
}

// checkResultWithMeta pairs a check result with its template definition.
type checkResultWithMeta struct {
	Def    *m365templates.M365CheckTemplate
	Result *checks.CheckResult
}

// checkToRisk converts a failed check result into an AurelianRisk output.
func checkToRisk(bag *databag.M365DataBag) func(checkResultWithMeta, *pipeline.P[model.AurelianModel]) error {
	return func(crm checkResultWithMeta, out *pipeline.P[model.AurelianModel]) error {
		def := crm.Def
		result := crm.Result

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
		return nil
	}
}

// containsStr checks if a string slice contains a value.
func containsStr(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}
