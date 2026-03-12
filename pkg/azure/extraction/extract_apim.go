package extraction

import (
	"encoding/json"
	"fmt"
	"log/slog"

	armapimanagement "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
)

func init() {
	mustRegister("microsoft.apimanagement/service", "apim-policies", extractAPIMPolicies)
	mustRegister("microsoft.apimanagement/service", "apim-backends", extractAPIMBackends)
	mustRegister("microsoft.apimanagement/service", "apim-namedvalues", extractAPIMNamedValues)
}

func extractAPIMPolicies(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	rg, serviceName, err := parseAPIMID(r.ResourceID)
	if err != nil {
		return err
	}

	client, err := armapimanagement.NewPolicyClient(r.SubscriptionID, ctx.Cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create APIM policy client: %w", err)
	}

	resp, err := client.ListByService(ctx.Context, rg, serviceName, nil)
	if err != nil {
		return handleExtractError(err, "apim-policies", r.ResourceID)
	}

	if resp.Value != nil {
		if data, merr := json.Marshal(resp.Value); merr == nil {
			out.Send(output.ScanInputFromAzureResource(r, "APIM Policies", data))
		}
	}
	return nil
}

func extractAPIMBackends(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	rg, serviceName, err := parseAPIMID(r.ResourceID)
	if err != nil {
		return err
	}

	client, err := armapimanagement.NewBackendClient(r.SubscriptionID, ctx.Cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create APIM backend client: %w", err)
	}

	pager := client.NewListByServicePager(rg, serviceName, nil)
	paginator := ratelimit.NewAzurePaginator()
	err = paginator.Paginate(func() (bool, error) {
		page, err := pager.NextPage(ctx.Context)
		if err != nil {
			return true, err
		}
		for _, backend := range page.Value {
			if backend.Properties == nil {
				continue
			}
			backendName := ""
			if backend.Name != nil {
				backendName = *backend.Name
			}
			if data, merr := json.Marshal(backend.Properties); merr == nil {
				label := fmt.Sprintf("APIM Backend: %s", backendName)
				out.Send(output.ScanInputFromAzureResource(r, label, data))
			}
		}
		return pager.More(), nil
	})
	return handleExtractError(err, "apim-backends", r.ResourceID)
}

func extractAPIMNamedValues(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	rg, serviceName, err := parseAPIMID(r.ResourceID)
	if err != nil {
		return err
	}

	namedValueClient, err := armapimanagement.NewNamedValueClient(r.SubscriptionID, ctx.Cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create APIM named value client: %w", err)
	}

	pager := namedValueClient.NewListByServicePager(rg, serviceName, nil)
	paginator := ratelimit.NewAzurePaginator()
	err = paginator.Paginate(func() (bool, error) {
		page, err := pager.NextPage(ctx.Context)
		if err != nil {
			return true, err
		}
		for _, nv := range page.Value {
			if nv.Properties == nil {
				continue
			}
			valueName := ""
			if nv.Name != nil {
				valueName = *nv.Name
			}

			// Try to get the actual secret value; this may fail with 403 for secret-type values.
			if valueName != "" {
				secretResp, secretErr := namedValueClient.ListValue(ctx.Context, rg, serviceName, valueName, nil)
				if secretErr != nil {
					if herr := handleExtractError(secretErr, "apim-namedvalues", r.ResourceID); herr != nil {
						slog.Warn("failed to list named value secret", "namedValue", valueName, "error", herr)
					}
				} else if secretResp.Value != nil {
					content, _ := json.Marshal(map[string]string{
						"name":  valueName,
						"value": *secretResp.Value,
					})
					label := fmt.Sprintf("APIM NamedValue: %s", valueName)
					out.Send(output.ScanInputFromAzureResource(r, label, content))
					continue
				}
			}

			// Fall back to the listed properties (which may not contain the actual secret value).
			if data, merr := json.Marshal(nv.Properties); merr == nil {
				label := fmt.Sprintf("APIM NamedValue: %s", valueName)
				out.Send(output.ScanInputFromAzureResource(r, label, data))
			}
		}
		return pager.More(), nil
	})
	return handleExtractError(err, "apim-namedvalues", r.ResourceID)
}

func parseAPIMID(resourceID string) (resourceGroup, serviceName string, err error) {
	_, rg, segments, parseErr := parseAzureResourceID(resourceID)
	if parseErr != nil {
		return "", "", fmt.Errorf("failed to parse APIM resource ID: %w", parseErr)
	}
	serviceName = segments["service"]
	if serviceName == "" {
		return "", "", fmt.Errorf("no 'service' segment in resource ID %s", resourceID)
	}
	return rg, serviceName, nil
}
