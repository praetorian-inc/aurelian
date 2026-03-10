package publicaccess

import (
	"encoding/json"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

// AccessEvaluator evaluates a GCPResource for public/anonymous access indicators
// and emits both the resource and an AurelianRisk if applicable.
type AccessEvaluator struct{}

// Evaluate sends the resource to out and, if public or anonymous access is detected,
// also emits an AurelianRisk.
func (e *AccessEvaluator) Evaluate(r output.GCPResource, out *pipeline.P[model.AurelianModel]) error {
	out.Send(r)

	hasPublicNetwork := len(r.IPs) > 0 || len(r.URLs) > 0
	hasAnonymousAccess := false
	if v, ok := r.Properties["AnonymousAccess"].(bool); ok {
		hasAnonymousAccess = v
	}

	if !hasPublicNetwork && !hasAnonymousAccess {
		return nil
	}

	var severity output.RiskSeverity
	var name string
	switch {
	case hasPublicNetwork && hasAnonymousAccess:
		severity = output.RiskSeverityHigh
		name = "public-anonymous-gcp-resource"
	case hasAnonymousAccess:
		severity = output.RiskSeverityMedium
		name = "anonymous-gcp-resource"
	default:
		severity = output.RiskSeverityMedium
		name = "public-gcp-resource"
	}

	ctx, _ := json.Marshal(map[string]any{
		"resourceType":    r.ResourceType,
		"resourceID":      r.ResourceID,
		"projectID":       r.ProjectID,
		"publicNetwork":   hasPublicNetwork,
		"anonymousAccess": hasAnonymousAccess,
		"ips":             r.IPs,
		"urls":            r.URLs,
	})

	out.Send(output.AurelianRisk{
		Name:        name,
		Severity:    severity,
		ImpactedResourceID: r.ResourceID,
		Context:     ctx,
	})

	return nil
}
