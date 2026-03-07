package recon

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/gcp/enumeration"
	"github.com/praetorian-inc/aurelian/pkg/gcp/extraction"
	"github.com/praetorian-inc/aurelian/pkg/gcp/hierarchy"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/secrets"
	"github.com/praetorian-inc/titus/pkg/types"
)

func init() {
	plugin.Register(&GCPFindSecretsModule{})
}

// GCPFindSecretsConfig holds the typed parameters for the GCP find-secrets module.
type GCPFindSecretsConfig struct {
	plugin.GCPCommonRecon
	secrets.ScannerConfig
	OutputDir string `param:"output-dir" desc:"Base output directory" default:"aurelian-output"`
}

// GCPFindSecretsModule scans GCP resources for hardcoded secrets using Titus.
type GCPFindSecretsModule struct {
	GCPFindSecretsConfig
}

func (m *GCPFindSecretsModule) ID() string                { return "find-secrets" }
func (m *GCPFindSecretsModule) Name() string              { return "GCP Find Secrets" }
func (m *GCPFindSecretsModule) Platform() plugin.Platform { return plugin.PlatformGCP }
func (m *GCPFindSecretsModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *GCPFindSecretsModule) OpsecLevel() string        { return "moderate" }
func (m *GCPFindSecretsModule) Authors() []string         { return []string{"Praetorian"} }

func (m *GCPFindSecretsModule) Description() string {
	return "Enumerates GCP resources via project hierarchy, extracts content likely to contain " +
		"hardcoded secrets (Compute metadata/startup scripts, Cloud Functions source, " +
		"Cloud Run environment variables, App Engine environment variables), and scans with Titus."
}

func (m *GCPFindSecretsModule) References() []string {
	return []string{
		"https://cloud.google.com/apis/docs/overview",
	}
}

func (m *GCPFindSecretsModule) SupportedResourceTypes() []string {
	return supportedInputTypes
}

func (m *GCPFindSecretsModule) Parameters() any {
	return &m.GCPFindSecretsConfig
}

// secretsResourceTypes are the GCP resource types that contain extractable secret content.
var secretsResourceTypes = []string{
	"compute.googleapis.com/Instance",
	"cloudfunctions.googleapis.com/Function",
	"run.googleapis.com/Service",
	"appengine.googleapis.com/Version",
}

func (m *GCPFindSecretsModule) Run(_ plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	c := m.GCPFindSecretsConfig
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

	// Resolve hierarchy: org/folder/project → project IDs.
	resolver := hierarchy.NewResolver(c.GCPCommonRecon)
	input := hierarchy.HierarchyResolverInput{
		OrgIDs:     c.OrgID,
		FolderIDs:  c.FolderID,
		ProjectIDs: c.ProjectID,
	}
	hierarchyStream := pipeline.From(input)
	resolved := pipeline.New[output.GCPResource]()
	pipeline.Pipe(hierarchyStream, resolver.Resolve, resolved)

	// Split: forward project IDs for enumeration.
	projects := pipeline.New[string]()
	pipeline.Pipe(resolved, splitHierarchyResources, projects)

	// Enumerate secrets-relevant resource types per project.
	enumerator := enumeration.NewEnumerator(c.GCPCommonRecon).ForTypes(secretsResourceTypes)
	listed := pipeline.New[output.GCPResource]()
	pipeline.Pipe(projects, enumerator.ListForProject, listed)

	// Extract content from resources.
	extractor := extraction.NewGCPExtractor(c.GCPCommonRecon)
	extracted := pipeline.New[output.ScanInput]()
	pipeline.Pipe(listed, extractor.Extract, extracted)

	// Scan for secrets.
	scanned := pipeline.New[secrets.SecretScanResult]()
	pipeline.Pipe(extracted, s.Scan, scanned)
	pipeline.Pipe(scanned, riskFromScanResult, out)

	return out.Wait()
}

func splitHierarchyResources(res output.GCPResource, p *pipeline.P[string]) error {
	if res.ResourceType == "projects" {
		p.Send(res.ProjectID)
	}
	return nil
}

func riskFromScanResult(result secrets.SecretScanResult, out *pipeline.P[model.AurelianModel]) error {
	proof := buildProofData(result, result.Match)
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
		Name:        formatSecretRiskName(result.Match.RuleID),
		Severity:    riskSeverityFromMatch(result.Match),
		ImpactedARN: impactedARN,
		Context:     proofBytes,
	})
	return nil
}

func extractRuleShortName(ruleID string) string {
	parts := strings.Split(ruleID, ".")
	if len(parts) >= 2 {
		return parts[1]
	}
	return strings.ToLower(ruleID)
}

func formatSecretRiskName(ruleID string) string {
	return fmt.Sprintf("gcp-secret-%s", extractRuleShortName(ruleID))
}

func riskSeverityFromMatch(match *types.Match) output.RiskSeverity {
	if match.ValidationResult != nil && match.ValidationResult.Status == types.StatusValid {
		return output.RiskSeverityHigh
	}
	return output.RiskSeverityMedium
}

func buildProofData(result secrets.SecretScanResult, match *types.Match) map[string]interface{} {
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
						"platform":      "gcp",
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
