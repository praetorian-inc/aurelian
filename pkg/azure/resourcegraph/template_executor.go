package resourcegraph

import (
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	azuretypes "github.com/praetorian-inc/aurelian/pkg/azure/types"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/templates"
)

// TemplateExecutor runs an ARG query template against a subscription.
type TemplateExecutor struct {
	cred azcore.TokenCredential
	tmpl *templates.ARGQueryTemplate
}

// NewTemplateExecutor creates a TemplateExecutor for the given template.
func NewTemplateExecutor(cred azcore.TokenCredential, tmpl *templates.ARGQueryTemplate) *TemplateExecutor {
	return &TemplateExecutor{cred: cred, tmpl: tmpl}
}

// Execute runs the template query against a subscription and sends results to out.
func (e *TemplateExecutor) Execute(sub azuretypes.SubscriptionInfo, out *pipeline.P[templates.ARGQueryResult]) error {
	return queryARG(e.cred, e.tmpl.Query, []string{sub.ID}, defaultPageSize, func(row map[string]any) error {
		result := parseTemplateRow(row, e.tmpl)
		if result.SubscriptionID == "" {
			result.SubscriptionID = sub.ID
		}
		out.Send(result)
		return nil
	})
}

// parseTemplateRow converts an ARG row into an ARGQueryResult.
func parseTemplateRow(row map[string]any, tmpl *templates.ARGQueryTemplate) templates.ARGQueryResult {
	result := templates.ARGQueryResult{
		TemplateID:      tmpl.ID,
		TemplateDetails: tmpl,
		ResourceID:      stringFromMap(row, "id"),
		ResourceName:    stringFromMap(row, "name"),
		ResourceType:    stringFromMap(row, "type"),
		Location:        stringFromMap(row, "location"),
		SubscriptionID:  stringFromMap(row, "subscriptionId"),
	}

	props := make(map[string]any)
	for k, v := range row {
		switch k {
		case "id", "name", "type", "location", "subscriptionId":
			continue
		default:
			props[k] = v
		}
	}
	if len(props) > 0 {
		result.Properties = props
	}

	return result
}
