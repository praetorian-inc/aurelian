// Package armenum provides ARM-direct enumeration for Azure resource types that
// are not indexed in the Azure Resource Graph "Resources" table:
//   - Microsoft.Resources/deployments  (no ARG table)
//   - Microsoft.Authorization/policyDefinitions  (in "policyresources" table, not "Resources")
//   - Microsoft.Blueprint/blueprints  (deprecated July 2026; not in "Resources")
package armenum

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/blueprint/armblueprint"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	azuretypes "github.com/praetorian-inc/aurelian/pkg/azure/types"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
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

	pager := client.NewListAtSubscriptionScopePager(nil)
	for pager.More() {
		page, err := pager.NextPage(contextBackground())
		if err != nil {
			return handleListError(err, "deployments", sub.ID)
		}
		for _, d := range page.Value {
			if d.ID == nil {
				continue
			}
			r := output.NewAzureResource(sub.ID, "Microsoft.Resources/deployments", *d.ID)
			r.SubscriptionName = sub.DisplayName
			r.TenantID = sub.TenantID
			if d.Name != nil {
				r.DisplayName = *d.Name
			}
			if d.Location != nil {
				r.Location = *d.Location
			}
			out.Send(r)
		}
	}
	return nil
}

func (e *ARMEnumerator) listPolicyDefinitions(sub azuretypes.SubscriptionInfo, out *pipeline.P[output.AzureResource]) error {
	client, err := armpolicy.NewDefinitionsClient(sub.ID, e.cred, nil)
	if err != nil {
		return fmt.Errorf("create policy definitions client: %w", err)
	}

	// List all definitions; filter to Custom client-side.
	// The server-side $filter for policyType is not reliably supported by the Go SDK.
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(contextBackground())
		if err != nil {
			return handleListError(err, "policyDefinitions", sub.ID)
		}
		for _, d := range page.Value {
			if d.ID == nil {
				continue
			}
			// Skip built-in and static policies — they don't contain customer secrets.
			if d.Properties != nil && d.Properties.PolicyType != nil &&
				*d.Properties.PolicyType != armpolicy.PolicyTypeCustom {
				continue
			}
			r := output.NewAzureResource(sub.ID, "Microsoft.Authorization/policyDefinitions", *d.ID)
			r.SubscriptionName = sub.DisplayName
			r.TenantID = sub.TenantID
			if d.Name != nil {
				r.DisplayName = *d.Name
			}
			out.Send(r)
		}
	}
	return nil
}

func (e *ARMEnumerator) listBlueprints(sub azuretypes.SubscriptionInfo, out *pipeline.P[output.AzureResource]) error {
	client, err := armblueprint.NewBlueprintsClient(e.cred, nil)
	if err != nil {
		return fmt.Errorf("create blueprints client: %w", err)
	}

	scope := fmt.Sprintf("/subscriptions/%s", sub.ID)
	pager := client.NewListPager(scope, nil)
	for pager.More() {
		page, err := pager.NextPage(contextBackground())
		if err != nil {
			return handleListError(err, "blueprints", sub.ID)
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
	}
	return nil
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
