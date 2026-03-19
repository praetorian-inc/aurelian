package recon

import (
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/aurelian/pkg/azure/armenum"
	"github.com/praetorian-inc/aurelian/pkg/azure/extraction"
	"github.com/praetorian-inc/aurelian/pkg/azure/resourcegraph"
	"github.com/praetorian-inc/aurelian/pkg/azure/subscriptions"
	azuretypes "github.com/praetorian-inc/aurelian/pkg/azure/types"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/secrets"
)

func init() {
	plugin.Register(&AzureFindSecretsModule{})
}

// AzureFindSecretsConfig holds the typed parameters for the Azure find-secrets module.
type AzureFindSecretsConfig struct {
	plugin.AzureCommonRecon
	secrets.ScannerConfig
	Concurrency      int      `param:"concurrency" desc:"Maximum concurrent API requests" default:"5"`
	ResourceID       []string `param:"resource-id" desc:"Azure resource ID(s) to scan directly, skipping enumeration" shortcode:"i"`
	MaxCosmosDocSize int      `param:"max-cosmos-doc-size" desc:"Max individual Cosmos document size in bytes" default:"1048576"`
	MaxCosmosDocScan int      `param:"max-cosmos-doc-scan" desc:"Max total Cosmos documents to scan per container (0 = unlimited)" default:"0"`
}

// AzureFindSecretsModule scans Azure resources for hardcoded secrets using Titus.
type AzureFindSecretsModule struct {
	AzureFindSecretsConfig
}

func (m *AzureFindSecretsModule) ID() string                { return "find-secrets" }
func (m *AzureFindSecretsModule) Name() string              { return "Azure Find Secrets" }
func (m *AzureFindSecretsModule) Platform() plugin.Platform { return plugin.PlatformAzure }
func (m *AzureFindSecretsModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *AzureFindSecretsModule) OpsecLevel() string        { return "moderate" }
func (m *AzureFindSecretsModule) Authors() []string         { return []string{"Praetorian"} }

func (m *AzureFindSecretsModule) Description() string {
	return "Enumerates Azure resources via Resource Graph, extracts content likely to contain " +
		"hardcoded secrets (VM user data, web app settings, automation variables, storage blobs, " +
		"container env vars, Cosmos DB, APIM named values, Key Vault, and 30+ other sources), " +
		"and scans with Titus."
}

func (m *AzureFindSecretsModule) References() []string {
	return []string{
		"https://learn.microsoft.com/en-us/azure/azure-resource-graph/overview",
	}
}

func (m *AzureFindSecretsModule) SupportedResourceTypes() []string {
	return []string{
		"Microsoft.Resources/subscriptions",
	}
}

func (m *AzureFindSecretsModule) Parameters() any {
	return &m.AzureFindSecretsConfig
}

func (m *AzureFindSecretsModule) Run(_ plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	c := m.AzureFindSecretsConfig
	c.Concurrency = max(1, c.Concurrency)
	if c.DBPath == "" {
		c.DBPath = secrets.DefaultDBPath(c.OutputDir)
	}

	var s secrets.SecretScanner
	if err := s.Start(c.ScannerConfig); err != nil {
		return fmt.Errorf("failed to create Titus scanner: %w", err)
	}
	defer func() {
		if closeErr := s.Close(); closeErr != nil {
			slog.Warn("failed to close Titus scanner", "error", closeErr)
		}
	}()

	// Branch: resource-level targeting (like AWS ResourceARN) vs subscription-wide scan.
	var listed *pipeline.P[output.AzureResource]
	if len(c.ResourceID) > 0 {
		var err error
		listed, err = m.listByResourceID(c)
		if err != nil {
			return err
		}
	} else {
		var err error
		listed, err = m.listBySubscription(c)
		if err != nil {
			return err
		}
	}

	extractor := extraction.NewAzureExtractor(c.AzureCredential)
	extractor.MaxCosmosDocSize = m.MaxCosmosDocSize
	extractor.MaxCosmosDocScan = m.MaxCosmosDocScan
	extracted := pipeline.New[output.ScanInput]()
	pipeOpts := &pipeline.PipeOpts{Concurrency: m.Concurrency}
	pipeline.Pipe(listed, extractor.Extract, extracted, pipeOpts)

	// Scan extracted content and convert results to risks.
	scanned := pipeline.New[secrets.SecretScanResult]()
	pipeline.Pipe(extracted, s.Scan, scanned)
	pipeline.Pipe(scanned, secrets.RiskFromScanResult, out)

	return out.Wait()
}

// listByResourceID builds AzureResource structs directly from user-provided resource IDs,
// skipping ARG and ARM enumeration entirely. Mirrors AWS's ResourceARN path.
// Hydrates each resource via ARG to populate Location, DisplayName, and TenantID
// which are not derivable from the resource ID string alone.
func (m *AzureFindSecretsModule) listByResourceID(c AzureFindSecretsConfig) (*pipeline.P[output.AzureResource], error) {
	resources := make([]output.AzureResource, 0, len(c.ResourceID))
	for _, id := range c.ResourceID {
		r, err := azureResourceFromID(id)
		if err != nil {
			slog.Warn("skipping invalid resource ID", "id", id, "error", err)
			continue
		}
		resources = append(resources, r)
	}

	if len(resources) == 0 && len(c.ResourceID) > 0 {
		return nil, fmt.Errorf("all %d provided resource IDs were invalid", len(c.ResourceID))
	}

	// Hydrate resources with metadata from ARG (location, name, tenantId).
	// Resources not in ARG (e.g., policy definitions) retain parsed-only fields.
	hydrateFromARG(c.AzureCredential, resources)

	return pipeline.From(resources...), nil
}

// listBySubscription runs the full ARG + ARM enumeration across subscriptions.
func (m *AzureFindSecretsModule) listBySubscription(c AzureFindSecretsConfig) (*pipeline.P[output.AzureResource], error) {
	resolver := subscriptions.NewSubscriptionResolver(c.AzureCredential)
	subscriptionIDs, err := resolveSubscriptionIDs(c.SubscriptionIDs, resolver)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve subscriptions: %w", err)
	}
	if len(subscriptionIDs) == 0 {
		slog.Warn("no accessible Azure subscriptions found")
		return pipeline.From[output.AzureResource](), nil
	}

	idStream := pipeline.From(subscriptionIDs...)

	resolvedSubs := pipeline.New[azuretypes.SubscriptionInfo]()
	pipeline.Pipe(idStream, resolver.Resolve, resolvedSubs)

	subsList, err := resolvedSubs.Collect()
	if err != nil {
		return nil, fmt.Errorf("failed to resolve subscriptions: %w", err)
	}

	// ARG path: enumerate resources discoverable via Resource Graph.
	argResolvedSubs := pipeline.From(subsList...)
	argInputs := pipeline.New[resourcegraph.ListerInput]()
	pipeline.Pipe(argResolvedSubs, m.toListerInput, argInputs)

	lister := resourcegraph.NewResourceGraphLister(c.AzureCredential, nil)
	argListed := pipeline.New[output.AzureResource]()
	pipeline.Pipe(argInputs, lister.List, argListed)

	// ARM path: enumerate resource types not indexed by ARG.
	armResolvedSubs := pipeline.From(subsList...)
	armEnumerator := armenum.NewARMEnumerator(c.AzureCredential)
	armListed := pipeline.New[output.AzureResource]()
	pipeline.Pipe(armResolvedSubs, armEnumerator.List, armListed)

	return pipeline.Merge(argListed, armListed), nil
}

// argResourceTypes lists all Azure resource types discoverable via Resource Graph
// that have registered extractors.
var argResourceTypes = []string{
	// Compute
	"Microsoft.Compute/virtualMachines",
	"Microsoft.Compute/virtualMachineScaleSets",
	"Microsoft.ContainerInstance/containerGroups",
	"Microsoft.App/containerApps",
	"Microsoft.HybridCompute/machines",

	// Web & App
	"Microsoft.Web/sites",
	"Microsoft.Web/staticSites",
	"Microsoft.Logic/workflows",
	"Microsoft.ApiManagement/service",

	// Automation
	"Microsoft.Automation/automationAccounts",

	// Storage & Data
	"Microsoft.Storage/storageAccounts",
	"Microsoft.AppConfiguration/configurationStores",
	"Microsoft.DocumentDB/databaseAccounts",
	"Microsoft.DataFactory/factories",
	"Microsoft.DigitalTwins/digitalTwinsInstances",
	"Microsoft.Synapse/workspaces",

	// DevOps & Analytics
	"Microsoft.ContainerRegistry/registries",
	"Microsoft.Insights/components",
	"Microsoft.Batch/batchAccounts",

	// IaC & Governance
	"Microsoft.Resources/templateSpecs",
	// NOTE: Microsoft.Resources/deployments, Microsoft.Authorization/policyDefinitions,
	// and Microsoft.Blueprint/blueprints are enumerated via the ARM direct path
	// (pkg/azure/armenum), not via ARG, since they are absent from the ARG "Resources" table.
}

func (m *AzureFindSecretsModule) toListerInput(sub azuretypes.SubscriptionInfo, out *pipeline.P[resourcegraph.ListerInput]) error {
	out.Send(resourcegraph.ListerInput{
		Subscription:  sub,
		ResourceTypes: argResourceTypes,
	})
	return nil
}

