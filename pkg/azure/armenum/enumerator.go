// Package armenum provides ARM-direct enumeration for Azure resource types that
// are not indexed in the Azure Resource Graph "Resources" table:
//   - Microsoft.Resources/deployments  (no ARG table)
//   - Microsoft.Authorization/policyDefinitions  (in "policyresources" table, not "Resources")
//   - Microsoft.Blueprint/blueprints  (deprecated July 2026; not in "Resources")
package armenum

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/blueprint/armblueprint"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	azuretypes "github.com/praetorian-inc/aurelian/pkg/azure/types"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
)

// ARMEnumeratedTypes lists the resource types this enumerator covers.
var ARMEnumeratedTypes = []string{
	"Microsoft.Resources/deployments",
	"Microsoft.Authorization/policyDefinitions",
	"Microsoft.Blueprint/blueprints",
}

// ARMEnumerator lists Azure resources that cannot be discovered via Resource Graph.
type ARMEnumerator struct {
	cred azcore.TokenCredential
}

// NewARMEnumerator creates an enumerator with the given credential.
func NewARMEnumerator(cred azcore.TokenCredential) *ARMEnumerator {
	return &ARMEnumerator{cred: cred}
}

// newPaginator returns a Paginator configured for Azure API throttling errors.
func newPaginator() *ratelimit.Paginator {
	return ratelimit.NewAzurePaginator()
}

// List enumerates ARM-only resource types for the given subscription.
func (e *ARMEnumerator) List(sub azuretypes.SubscriptionInfo, out *pipeline.P[output.AzureResource]) error {
	if err := e.listDeployments(sub, out); err != nil {
		return err
	}
	if err := e.listPolicyDefinitions(sub, out); err != nil {
		return err
	}
	if err := e.listBlueprints(sub, out); err != nil {
		return err
	}
	return nil
}

func (e *ARMEnumerator) listDeployments(sub azuretypes.SubscriptionInfo, out *pipeline.P[output.AzureResource]) error {
	client, err := armresources.NewDeploymentsClient(sub.ID, e.cred, nil)
	if err != nil {
		return fmt.Errorf("create deployments client: %w", err)
	}

	// Subscription-scope deployments (created without a resource group).
	subPager := client.NewListAtSubscriptionScopePager(nil)
	paginator := newPaginator()
	if err := paginator.Paginate(func() (bool, error) {
		page, err := subPager.NextPage(context.Background())
		if err != nil {
			return false, handleListError(err, "deployments-subscription", sub.ID)
		}
		for _, d := range page.Value {
			emitDeployment(d.ID, d.Name, d.Location, sub, out)
		}
		return subPager.More(), nil
	}); err != nil {
		return err
	}

	// Resource-group-scope deployments: iterate all resource groups.
	rgClient, err := armresources.NewResourceGroupsClient(sub.ID, e.cred, nil)
	if err != nil {
		return fmt.Errorf("create resource groups client: %w", err)
	}

	rgPager := rgClient.NewListPager(nil)
	rgPaginator := newPaginator()
	if err := rgPaginator.Paginate(func() (bool, error) {
		rgPage, err := rgPager.NextPage(context.Background())
		if err != nil {
			return false, handleListError(err, "resourceGroups", sub.ID)
		}
		for _, rg := range rgPage.Value {
			if rg.Name == nil {
				continue
			}
			rgDeployPager := client.NewListByResourceGroupPager(*rg.Name, nil)
			deployPaginator := newPaginator()
			if pErr := deployPaginator.Paginate(func() (bool, error) {
				page, err := rgDeployPager.NextPage(context.Background())
				if err != nil {
					slog.Warn("ARM enumeration skipped (listing deployments in resource group)",
						"rg", *rg.Name, "subscription", sub.ID, "error", err)
					return false, nil
				}
				for _, d := range page.Value {
					emitDeployment(d.ID, d.Name, d.Location, sub, out)
				}
				return rgDeployPager.More(), nil
			}); pErr != nil {
				return false, pErr
			}
		}
		return rgPager.More(), nil
	}); err != nil {
		return err
	}

	return nil
}

func emitDeployment(id, name, location *string, sub azuretypes.SubscriptionInfo, out *pipeline.P[output.AzureResource]) {
	if id == nil {
		return
	}
	r := output.NewAzureResource(sub.ID, "Microsoft.Resources/deployments", *id)
	r.SubscriptionName = sub.DisplayName
	r.TenantID = sub.TenantID
	if name != nil {
		r.DisplayName = *name
	}
	if location != nil {
		r.Location = *location
	}
	out.Send(r)
}

func (e *ARMEnumerator) listPolicyDefinitions(sub azuretypes.SubscriptionInfo, out *pipeline.P[output.AzureResource]) error {
	// Use raw JSON pagination instead of the typed SDK client.
	// The armpolicy SDK's typed unmarshaller crashes when custom policy definitions
	// contain metadata type mismatches (e.g., "assignPermissions": "true" instead of
	// true). This is a known issue with production tenants where custom policies have
	// non-conforming metadata. Raw JSON lets us tolerate malformed fields gracefully.
	pipeline, err := newRawPolicyPager(sub.ID, e.cred)
	if err != nil {
		return fmt.Errorf("create policy definitions pager: %w", err)
	}

	paginator := newPaginator()
	return paginator.Paginate(func() (bool, error) {
		defs, nextLink, err := pipeline.nextPage()
		if err != nil {
			return false, handleListError(err, "policyDefinitions", sub.ID)
		}
		for _, d := range defs {
			if d.ID == "" {
				continue
			}
			// Skip built-in and static policies — they don't contain customer secrets.
			if d.Properties.PolicyType != "" && d.Properties.PolicyType != "Custom" {
				continue
			}
			r := output.NewAzureResource(sub.ID, "Microsoft.Authorization/policyDefinitions", d.ID)
			r.SubscriptionName = sub.DisplayName
			r.TenantID = sub.TenantID
			r.DisplayName = d.Properties.DisplayName
			out.Send(r)
		}
		return nextLink != "", nil
	})
}

func (e *ARMEnumerator) listBlueprints(sub azuretypes.SubscriptionInfo, out *pipeline.P[output.AzureResource]) error {
	client, err := armblueprint.NewBlueprintsClient(e.cred, nil)
	if err != nil {
		return fmt.Errorf("create blueprints client: %w", err)
	}

	scope := fmt.Sprintf("/subscriptions/%s", sub.ID)
	pager := client.NewListPager(scope, nil)
	paginator := newPaginator()
	return paginator.Paginate(func() (bool, error) {
		page, err := pager.NextPage(context.Background())
		if err != nil {
			return false, handleListError(err, "blueprints", sub.ID)
		}
		for _, b := range page.Value {
			if b.ID == nil {
				continue
			}
			r := output.NewAzureResource(sub.ID, "Microsoft.Blueprint/blueprints", *b.ID)
			r.SubscriptionName = sub.DisplayName
			r.TenantID = sub.TenantID
			if b.Name != nil {
				r.DisplayName = *b.Name
			}
			out.Send(r)
		}
		return pager.More(), nil
	})
}

// handleListError suppresses permission/throttle errors and returns all others.
func handleListError(err error, resourceKind, subscriptionID string) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if isAuthOrThrottle(msg) {
		slog.Warn("ARM enumeration skipped (permission/throttle)",
			"kind", resourceKind,
			"subscription", subscriptionID,
			"error", msg,
		)
		return nil
	}
	return fmt.Errorf("ARM list %s in %s: %w", resourceKind, subscriptionID, err)
}

func isAuthOrThrottle(msg string) bool {
	for _, kw := range []string{
		"AuthorizationFailed", "AuthenticationFailed",
		"LinkedAuthorizationFailed",
		fmt.Sprintf("%d", http.StatusForbidden),
		fmt.Sprintf("%d", http.StatusUnauthorized),
		fmt.Sprintf("%d", http.StatusNotFound),
		fmt.Sprintf("%d", http.StatusTooManyRequests),
	} {
		if strings.Contains(msg, kw) {
			return true
		}
	}
	return false
}

// isDeserializationError returns true if the error indicates a JSON/XML
// unmarshalling failure from the Azure SDK. These occur when the API returns
// fields or types that the SDK structs don't expect (e.g., newer API schema).
func isDeserializationError(msg string) bool {
	for _, kw := range []string{
		"cannot unmarshal",
		"unmarshalling type",
		"error decoding",
		"invalid character",
		"unexpected end of JSON",
		"xml:",
	} {
		if strings.Contains(msg, kw) {
			return true
		}
	}
	return false
}
