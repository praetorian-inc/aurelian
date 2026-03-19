package extraction

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/blueprint/armblueprint"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armtemplatespecs"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

func init() {
	mustRegister("microsoft.resources/templatespecs", "template-spec-versions", extractTemplateSpecVersions)
	mustRegister("microsoft.blueprint/blueprints", "blueprint-artifacts", extractBlueprintArtifacts)
	mustRegister("microsoft.authorization/policydefinitions", "policy-definitions", extractPolicyDefinitions)
}

// extractTemplateSpecVersions lists all versions of a Template Spec and marshals each version's template content.
func extractTemplateSpecVersions(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	_, resourceGroup, segments, err := ParseAzureResourceID(r.ResourceID)
	if err != nil {
		return fmt.Errorf("failed to parse template spec resource ID: %w", err)
	}
	templateSpecName := segments["templateSpecs"]
	if templateSpecName == "" {
		return fmt.Errorf("no templateSpecs segment in resource ID %s", r.ResourceID)
	}

	client, err := armtemplatespecs.NewTemplateSpecVersionsClient(r.SubscriptionID, ctx.Cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create template spec versions client: %w", err)
	}

	pager := client.NewListPager(resourceGroup, templateSpecName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx.Context)
		if err != nil {
			return handleExtractError(err, "template-spec-versions", r.ResourceID)
		}
		for _, version := range page.Value {
			if version.Properties == nil {
				continue
			}
			content, err := json.Marshal(version.Properties)
			if err != nil {
				continue
			}
			versionName := ""
			if version.Name != nil {
				versionName = *version.Name
			}
			label := fmt.Sprintf("TemplateSpec Version: %s", versionName)
			out.Send(output.ScanInputFromAzureResource(r, label, content))
		}
	}

	return nil
}

// extractBlueprintArtifacts lists artifacts for a Blueprint definition.
// Note: Azure Blueprints are deprecated as of July 2026.
func extractBlueprintArtifacts(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	_, _, segments, err := ParseAzureResourceID(r.ResourceID)
	if err != nil {
		return fmt.Errorf("failed to parse blueprint resource ID: %w", err)
	}
	blueprintName := segments["blueprints"]
	if blueprintName == "" {
		return fmt.Errorf("no blueprints segment in resource ID %s", r.ResourceID)
	}

	client, err := armblueprint.NewArtifactsClient(ctx.Cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create blueprint artifacts client: %w", err)
	}

	// resourceScope is the subscription scope portion of the resource ID
	resourceScope := fmt.Sprintf("/subscriptions/%s", r.SubscriptionID)

	pager := client.NewListPager(resourceScope, blueprintName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx.Context)
		if err != nil {
			return handleExtractError(err, "blueprint-artifacts", r.ResourceID)
		}
		for _, artifact := range page.Value {
			if artifact == nil {
				continue
			}
			content, err := json.Marshal(artifact)
			if err != nil {
				continue
			}
			label := fmt.Sprintf("Blueprint Artifact: %s", blueprintName)
			out.Send(output.ScanInputFromAzureResource(r, label, content))
		}
	}

	return nil
}

// extractPolicyDefinitions retrieves and marshals a custom policy definition's rule.
func extractPolicyDefinitions(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	// Policy definitions are subscription-scope resources:
	// /subscriptions/{sub}/providers/Microsoft.Authorization/policyDefinitions/{name}
	// ParseAzureResourceID requires a resource group, so extract the name from the last path segment.
	parts := strings.Split(r.ResourceID, "/")
	policyName := parts[len(parts)-1]
	if policyName == "" {
		return fmt.Errorf("could not extract policy name from resource ID %s", r.ResourceID)
	}

	client, err := armpolicy.NewDefinitionsClient(r.SubscriptionID, ctx.Cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create policy definitions client: %w", err)
	}

	result, err := client.Get(ctx.Context, policyName, nil)
	if err != nil {
		return handleExtractError(err, "policy-definitions", r.ResourceID)
	}

	if result.Properties == nil {
		return nil
	}

	content, err := json.Marshal(result.Properties)
	if err != nil {
		return fmt.Errorf("failed to marshal policy definition: %w", err)
	}

	label := fmt.Sprintf("Policy Definition: %s", policyName)
	out.Send(output.ScanInputFromAzureResource(r, label, content))

	return nil
}
