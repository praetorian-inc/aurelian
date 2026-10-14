package extraction

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAllExtractorsRegistered(t *testing.T) {
	tests := []struct {
		resourceType  string
		expectedNames []string
	}{
		{"microsoft.containerregistry/registries", []string{"acr-tasks"}},
		{"microsoft.apimanagement/service", []string{"apim-policies", "apim-backends", "apim-namedvalues"}},
		{"microsoft.appconfiguration/configurationstores", []string{"app-config-keyvalues"}},
		{"microsoft.insights/components", []string{"app-insights-keys"}},
		{"microsoft.hybridcompute/machines", []string{"arc-extensions"}},
		{"microsoft.automation/automationaccounts", []string{"automation-variables", "automation-runbooks"}},
		{"microsoft.batch/batchaccounts", []string{"batch-pool-starttasks"}},
		{"microsoft.app/containerapps", []string{"container-app-envvars"}},
		{"microsoft.containerinstance/containergroups", []string{"container-instance-envvars"}},
		{"microsoft.documentdb/databaseaccounts", []string{"cosmos-server-side-code", "cosmos-config-docs"}},
		{"microsoft.datafactory/factories", []string{"adf-pipelines", "adf-linkedservices"}},
		{"microsoft.resources/deployments", []string{"deployment-params"}},
		{"microsoft.digitaltwins/digitaltwinsinstances", []string{"digitaltwins-properties"}},
		{"microsoft.resources/templatespecs", []string{"template-spec-versions"}},
		{"microsoft.blueprint/blueprints", []string{"blueprint-artifacts"}},
		{"microsoft.authorization/policydefinitions", []string{"policy-definitions"}},
		{"microsoft.logic/workflows", []string{"logic-app-definition"}},
		{"microsoft.web/staticsites", []string{"static-webapp-settings"}},
		{"microsoft.storage/storageaccounts", []string{"storage-blobs"}},
		{"microsoft.synapse/workspaces", []string{"synapse-properties"}},
		{"microsoft.compute/virtualmachines", []string{"vm-userdata", "vm-extensions", "vm-bootdiag"}},
		{"microsoft.compute/virtualmachinescalesets", []string{"vmss-userdata", "vmss-extensions"}},
		{"microsoft.web/sites", []string{"webapp-settings", "webapp-connections", "webapp-hostkeys", "webapp-slots", "webapp-siteconfig"}},
	}
	for _, tt := range tests {
		t.Run(tt.resourceType, func(t *testing.T) {
			extractors := getExtractors(tt.resourceType)
			assert.NotEmpty(t, extractors, "expected extractors registered for %s", tt.resourceType)
			names := make(map[string]bool, len(extractors))
			for _, e := range extractors {
				names[e.Name] = true
			}
			for _, want := range tt.expectedNames {
				assert.True(t, names[want], "extractor %q not registered for %s", want, tt.resourceType)
			}
		})
	}
}

func TestExtractDiagnostics_NotRegistered(t *testing.T) {
	var fn extractorFunc = extractDiagnosticSettings
	assert.NotNil(t, fn, "extractDiagnosticSettings should be a valid extractorFunc")
}
