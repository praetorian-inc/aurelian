package publicaccess

import (
	"fmt"
	"log/slog"
	"strconv"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/publicresource"
)

// AccessEvaluator evaluates a GCPResource for public/anonymous access indicators
// and emits both the resource and a capmodel.Risk if applicable.
type AccessEvaluator struct{}

// Evaluate sends the resource to out and, if public or anonymous access is
// detected, also emits a standardized public-resource capmodel.Risk.
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
	var name, summary string
	switch {
	case hasPublicNetwork && hasAnonymousAccess:
		severity, name = output.RiskSeverityHigh, "public-anonymous-gcp-resource"
		summary = fmt.Sprintf("GCP resource %s (%s) in project %s is reachable from the internet and allows anonymous access.", r.ResourceID, r.ResourceType, r.ProjectID)
	case hasAnonymousAccess:
		severity, name = output.RiskSeverityMedium, "anonymous-gcp-resource"
		summary = fmt.Sprintf("GCP resource %s (%s) in project %s allows anonymous access.", r.ResourceID, r.ResourceType, r.ProjectID)
	default:
		severity, name = output.RiskSeverityMedium, "public-gcp-resource"
		summary = fmt.Sprintf("GCP resource %s (%s) in project %s has public network exposure.", r.ResourceID, r.ResourceType, r.ProjectID)
	}

	risk, err := publicresource.NewRisk(publicresource.PublicResource{
		Provider:     "GCP",
		RiskName:     name,
		ResourceType: r.ResourceType,
		ResourceID:   r.ResourceID,
		ResourceName: r.DisplayName,
		Region:       r.Location,
		Scope:        r.ProjectID,
		ScopeLabel:   "GCP Project",
		Severity:     severity,
		Summary:      summary,
		Exposure: []publicresource.Fact{
			{Key: "Public Network", Value: strconv.FormatBool(hasPublicNetwork)},
			{Key: "Anonymous Access", Value: strconv.FormatBool(hasAnonymousAccess)},
		},
		Lists: []publicresource.NamedList{
			{Title: "Public IPs", Items: r.IPs},
			{Title: "Public URLs", Items: r.URLs},
		},
		Properties: r.Properties,
	})
	if err != nil {
		slog.Warn("failed to build public resource risk", "resource", r.ResourceID, "error", err)
		return nil
	}

	out.Send(risk)
	return nil
}
