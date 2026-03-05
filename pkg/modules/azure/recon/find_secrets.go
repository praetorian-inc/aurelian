package recon

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

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
		"hardcoded secrets (VM user data, web app settings, automation account variables, " +
		"storage account blobs), and scans with Titus."
}

func (m *AzureFindSecretsModule) References() []string {
	return []string{
		"https://learn.microsoft.com/en-us/azure/azure-resource-graph/overview",
	}
}

func (m *AzureFindSecretsModule) SupportedResourceTypes() []string {
	return []string{
		"Microsoft.Compute/virtualMachines",
		"Microsoft.Web/sites",
		"Microsoft.Automation/automationAccounts",
		"Microsoft.Storage/storageAccounts",
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
	subscriptionIDs, err := resolveSubscriptionIDs(c.AzureCommonRecon, resolver)
	if err != nil {
		return fmt.Errorf("failed to resolve subscriptions: %w", err)
	}
	if len(subscriptionIDs) == 0 {
		slog.Warn("no accessible Azure subscriptions found")
		return nil
	}

	idStream := pipeline.From(subscriptionIDs...)
	resolvedSubs := pipeline.New[azuretypes.SubscriptionInfo]()
	pipeline.Pipe(idStream, resolver.Resolve, resolvedSubs)

	inputs := pipeline.New[resourcegraph.ListerInput]()
	pipeline.Pipe(resolvedSubs, m.toListerInput, inputs)

	lister := resourcegraph.NewResourceGraphLister(c.AzureCredential, nil)
	listed := pipeline.New[output.AzureResource]()
	pipeline.Pipe(inputs, lister.List, listed)

	extractor := extraction.NewAzureExtractor(c.AzureCredential)
	extracted := pipeline.New[output.ScanInput]()
	pipeline.Pipe(listed, extractor.Extract, extracted)

	scanned := pipeline.New[secrets.SecretScanResult]()
	pipeline.Pipe(extracted, s.Scan, scanned)
	pipeline.Pipe(scanned, azureRiskFromScanResult, out)

	return out.Wait()
}

func (m *AzureFindSecretsModule) toListerInput(sub azuretypes.SubscriptionInfo, out *pipeline.P[resourcegraph.ListerInput]) error {
	out.Send(resourcegraph.ListerInput{
		Subscription:  sub,
		ResourceTypes: m.SupportedResourceTypes(),
	})
	return nil
}

func resolveSubscriptionIDs(opts plugin.AzureCommonRecon, resolver *subscriptions.SubscriptionResolver) ([]string, error) {
	ids := opts.SubscriptionID
	requestsAll := len(ids) == 1 && strings.EqualFold(ids[0], "all")
	if !requestsAll {
		return ids, nil
	}

	subs, err := resolver.ListAllSubscriptions()
	if err != nil {
		return nil, fmt.Errorf("failed to list subscriptions: %w", err)
	}

	resolvedIDs := make([]string, 0, len(subs))
	for _, sub := range subs {
		resolvedIDs = append(resolvedIDs, sub.ID)
	}
	return resolvedIDs, nil
}

func azureRiskFromScanResult(result secrets.SecretScanResult, out *pipeline.P[model.AurelianModel]) error {
	proof := buildAzureProofData(result, result.Match)
	proofBytes, err := json.MarshalIndent(proof, "", "  ")
	if err != nil {
		slog.Warn("failed to marshal proof", "resource", result.ResourceRef, "error", err)
		return nil
	}

	impactedARN := result.ResourceRef
	if result.Match.FindingID != "" {
		findingPrefix := result.Match.FindingID
		if len(findingPrefix) > 8 {
			findingPrefix = findingPrefix[:8]
		}
		impactedARN = fmt.Sprintf("%s:%s", result.ResourceRef, findingPrefix)
	}

	out.Send(output.AurelianRisk{
		Name:        formatAzureSecretRiskName(result.Match.RuleID),
		Severity:    azureRiskSeverityFromMatch(result.Match),
		ImpactedARN: impactedARN,
		Context:     proofBytes,
	})
	return nil
}

func formatAzureSecretRiskName(ruleID string) string {
	parts := strings.Split(ruleID, ".")
	shortName := strings.ToLower(ruleID)
	if len(parts) >= 2 {
		shortName = parts[1]
	}
	return fmt.Sprintf("azure-secret-%s", shortName)
}

func azureRiskSeverityFromMatch(match *types.Match) output.RiskSeverity {
	if match.ValidationResult != nil && match.ValidationResult.Status == types.StatusValid {
		return output.RiskSeverityHigh
	}
	return output.RiskSeverityMedium
}

func buildAzureProofData(result secrets.SecretScanResult, match *types.Match) map[string]interface{} {
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
