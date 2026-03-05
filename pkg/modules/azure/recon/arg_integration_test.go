//go:build integration

package recon

import (
	"testing"

	"github.com/praetorian-inc/aurelian/test/testutil"
)

func TestARG_AKSLocalAccountsEnabled(t *testing.T) {
	fixture := testutil.NewAzureFixture(t, "azure/recon/arg/aks-local-accounts-enabled")
	fixture.Setup()
	t.Skip("skeleton — enricher/module implementation pending")
}

func TestARG_AKSRBACDisabled(t *testing.T) {
	fixture := testutil.NewAzureFixture(t, "azure/recon/arg/aks-rbac-disabled")
	fixture.Setup()
	t.Skip("skeleton — enricher/module implementation pending")
}

func TestARG_AppServiceAuthDisabled(t *testing.T) {
	fixture := testutil.NewAzureFixture(t, "azure/recon/arg/app-service-auth-disabled")
	fixture.Setup()
	t.Skip("skeleton — enricher/module implementation pending")
}

func TestARG_AppServiceRemoteDebugging(t *testing.T) {
	fixture := testutil.NewAzureFixture(t, "azure/recon/arg/app-service-remote-debugging")
	fixture.Setup()
	t.Skip("skeleton — enricher/module implementation pending")
}

func TestARG_DatabasesAllowAzureServices(t *testing.T) {
	fixture := testutil.NewAzureFixture(t, "azure/recon/arg/databases-allow-azure-services")
	fixture.Setup()
	t.Skip("skeleton — enricher/module implementation pending")
}

func TestARG_EventGridPublicAccess(t *testing.T) {
	fixture := testutil.NewAzureFixture(t, "azure/recon/arg/event-grid-public-access")
	fixture.Setup()
	t.Skip("skeleton — enricher/module implementation pending")
}

func TestARG_FunctionAppsPublicExposure(t *testing.T) {
	fixture := testutil.NewAzureFixture(t, "azure/recon/arg/function-apps-public-exposure")
	fixture.Setup()
	t.Skip("skeleton — enricher/module implementation pending")
}

func TestARG_FunctionAppHTTPAnonymousAccess(t *testing.T) {
	fixture := testutil.NewAzureFixture(t, "azure/recon/arg/function-app-http-anonymous-access")
	fixture.Setup()
	t.Skip("skeleton — enricher/module implementation pending")
}

func TestARG_FunctionAppsPublicHTTPTriggers(t *testing.T) {
	fixture := testutil.NewAzureFixture(t, "azure/recon/arg/function-apps-public-http-triggers")
	fixture.Setup()
	t.Skip("skeleton — enricher/module implementation pending")
}

func TestARG_OpenAIPublicAccess(t *testing.T) {
	fixture := testutil.NewAzureFixture(t, "azure/recon/arg/openai-public-access")
	fixture.Setup()
	t.Skip("skeleton — enricher/module implementation pending")
}

func TestARG_NebulaPublicAccess(t *testing.T) {
	fixture := testutil.NewAzureFixture(t, "azure/recon/arg/nebula-public-access")
	fixture.Setup()
	t.Skip("skeleton — enricher/module implementation pending")
}

func TestARG_AutomationSecrets(t *testing.T) {
	fixture := testutil.NewAzureFixture(t, "azure/recon/arg/automation-secrets")
	fixture.Setup()
	t.Skip("skeleton — enricher/module implementation pending")
}

func TestARG_KeyVaultAccessPolicyPrivilegeEscalation(t *testing.T) {
	fixture := testutil.NewAzureFixture(t, "azure/recon/arg/key-vault-access-policy-privilege-escalation")
	fixture.Setup()
	t.Skip("skeleton — enricher/module implementation pending")
}

func TestARG_KustoWildcardTrustedTenants(t *testing.T) {
	fixture := testutil.NewAzureFixture(t, "azure/recon/arg/kusto-wildcard-trusted-tenants")
	fixture.Setup()
	t.Skip("skeleton — enricher/module implementation pending")
}

func TestARG_OverprivilegedCustomRoles(t *testing.T) {
	fixture := testutil.NewAzureFixture(t, "azure/recon/arg/overprivileged-custom-roles")
	fixture.Setup()
	t.Skip("skeleton — enricher/module implementation pending")
}

func TestARG_StorageAccountsCloudShell(t *testing.T) {
	fixture := testutil.NewAzureFixture(t, "azure/recon/arg/storage-accounts-cloud-shell")
	fixture.Setup()
	t.Skip("skeleton — enricher/module implementation pending")
}

func TestARG_VMUserdataSecrets(t *testing.T) {
	fixture := testutil.NewAzureFixture(t, "azure/recon/arg/vm-userdata-secrets")
	fixture.Setup()
	t.Skip("skeleton — enricher/module implementation pending")
}

func TestARG_WebappSecrets(t *testing.T) {
	fixture := testutil.NewAzureFixture(t, "azure/recon/arg/webapp-secrets")
	fixture.Setup()
	t.Skip("skeleton — enricher/module implementation pending")
}
