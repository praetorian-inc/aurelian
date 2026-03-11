package recon

import (
	"encoding/json"
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
	"github.com/praetorian-inc/titus/pkg/types"
)

func init() {
	plugin.Register(&AzureFindSecretsModule{})
}

// AzureFindSecretsConfig holds the typed parameters for the Azure find-secrets module.
type AzureFindSecretsConfig struct {
	plugin.AzureCommonRecon
	secrets.ScannerConfig
	MaxCosmosDocSize int `param:"max-cosmos-doc-size" desc:"Max individual Cosmos document size in bytes" default:"1048576"`
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
	if c.DBPath == "" {
		c.DBPath = secrets.DefaultDBPath(c.OutputDir)
	}

	var s secrets.SecretScanner
	if err := s.Start(c.DBPath, c.DisabledTitusRules); err != nil {
		return fmt.Errorf("failed to create Titus scanner: %w", err)
	}
	defer func() {
		if closeErr := s.Close(); closeErr != nil {
			slog.Warn("failed to close Titus scanner", "error", closeErr)
		}
	}()

	resolver := subscriptions.NewSubscriptionResolver(c.AzureCredential)
	subscriptionIDs, err := resolveSubscriptionIDs(c.SubscriptionIDs, resolver)
	if err != nil {
		return fmt.Errorf("failed to resolve subscriptions: %w", err)
	}
	if len(subscriptionIDs) == 0 {
		slog.Warn("no accessible Azure subscriptions found")
		return nil
	}

	// Resolve subscriptions once, then fan out to both paths.
	idStream := pipeline.From(subscriptionIDs...)

	resolvedSubs := pipeline.New[azuretypes.SubscriptionInfo]()
	pipeline.Pipe(idStream, resolver.Resolve, resolvedSubs)

	subsList, err := resolvedSubs.Collect()
	if err != nil {
		return fmt.Errorf("failed to resolve subscriptions: %w", err)
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

	// Merge both enumeration paths and extract secrets.
	listed := pipeline.Merge(argListed, armListed)

	extractor := extraction.NewAzureExtractor(c.AzureCredential)
	extractor.MaxCosmosDocSize = m.MaxCosmosDocSize
	extracted := pipeline.New[output.ScanInput]()
	pipeline.Pipe(listed, extractor.Extract, extracted)

	// Scan extracted content and convert results to risks.
	scanned := pipeline.New[secrets.SecretScanResult]()
	pipeline.Pipe(extracted, s.Scan, scanned)
	pipeline.Pipe(scanned, m.riskFromScanResult, out)

	return out.Wait()
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

func (m *AzureFindSecretsModule) riskFromScanResult(result secrets.SecretScanResult, out *pipeline.P[model.AurelianModel]) error {
	proof := m.buildProofData(result, result.Match)
	proofBytes, err := json.MarshalIndent(proof, "", "  ")
	if err != nil {
		slog.Warn("failed to marshal proof", "resource", result.ResourceRef, "error", err)
		return nil
	}

	out.Send(secrets.NewSecretRisk(result, "azure", proofBytes))
	return nil
}

func (m *AzureFindSecretsModule) buildProofData(result secrets.SecretScanResult, match *types.Match) map[string]interface{} {
	proof := map[string]interface{}{
		"finding_id":   match.FindingID,
		"rule_name":    match.RuleName,
		"rule_text_id": match.RuleID,
		"resource_ref": result.ResourceRef,
		"num_matches":  1,
		"matches": []map[string]interface{}{
			{
				"provenance": []map[string]interface{}{
					{
						"kind":          "cloud_resource",
						"platform":      "azure",
						"resource_id":   result.ResourceRef,
						"resource_type": result.ResourceType,
						"region":        result.Region,
						"account_id":    result.AccountID,
						"first_commit": map[string]interface{}{
							"blob_path": result.Label,
						},
					},
				},
				"snippet": map[string]string{
					"before":   string(match.Snippet.Before),
					"matching": string(match.Snippet.Matching),
					"after":    string(match.Snippet.After),
				},
				"location": map[string]interface{}{
					"offset_span": map[string]interface{}{
						"start": match.Location.Offset.Start,
						"end":   match.Location.Offset.End,
					},
					"source_span": map[string]interface{}{
						"start": map[string]interface{}{
							"line":   match.Location.Source.Start.Line,
							"column": match.Location.Source.Start.Column,
						},
						"end": map[string]interface{}{
							"line":   match.Location.Source.End.Line,
							"column": match.Location.Source.End.Column,
						},
					},
				},
			},
		},
	}

	if match.ValidationResult != nil {
		proof["validation"] = map[string]interface{}{
			"status":     string(match.ValidationResult.Status),
			"confidence": match.ValidationResult.Confidence,
			"message":    match.ValidationResult.Message,
		}
	}

	return proof
}
