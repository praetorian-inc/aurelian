package recon

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	cclist "github.com/praetorian-inc/aurelian/pkg/aws/cloudcontrol"
	"github.com/praetorian-inc/aurelian/pkg/aws/extraction"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/secrets"
	"github.com/praetorian-inc/titus/pkg/types"
)

func init() {
	plugin.Register(&AWSFindSecretsModule{})
}

// FindSecretsConfig holds the typed parameters for the find-secrets module.
type FindSecretsConfig struct {
	plugin.AWSCommonRecon
	secrets.ScannerConfig
	MaxEvents  int `param:"max-events" desc:"Max log events per log group" default:"10000"`
	MaxStreams int `param:"max-streams" desc:"Max streams to sample per log group" default:"10"`
}

// AWSFindSecretsModule scans AWS resources for hardcoded secrets using Titus.
type AWSFindSecretsModule struct {
	FindSecretsConfig
}

func (m *AWSFindSecretsModule) ID() string                { return "find-secrets" }
func (m *AWSFindSecretsModule) Name() string              { return "AWS Find Secrets" }
func (m *AWSFindSecretsModule) Platform() plugin.Platform { return plugin.PlatformAWS }
func (m *AWSFindSecretsModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *AWSFindSecretsModule) OpsecLevel() string        { return "moderate" }
func (m *AWSFindSecretsModule) Authors() []string         { return []string{"Praetorian"} }

func (m *AWSFindSecretsModule) Description() string {
	return "Enumerates AWS resources via Cloud Control, extracts content likely to contain " +
		"hardcoded secrets (EC2 user data, Lambda code, CloudFormation templates, CloudWatch logs, " +
		"ECS task definitions, SSM documents, Step Functions executions), and scans with Titus."
}

func (m *AWSFindSecretsModule) References() []string {
	return []string{
		"https://docs.aws.amazon.com/cloudcontrolapi/latest/userguide/supported-resources.html",
	}
}

func (m *AWSFindSecretsModule) SupportedResourceTypes() []string {
	return []string{
		"AWS::EC2::Instance",
		"AWS::Lambda::Function",
		"AWS::CloudFormation::Stack",
		"AWS::Logs::LogGroup",
		"AWS::ECS::TaskDefinition",
		"AWS::SSM::Document",
		"AWS::StepFunctions::StateMachine",
		// TODO: AWS::ECR::Repository — container image scanning deferred to follow-up PR.
	}
}

func (m *AWSFindSecretsModule) Parameters() any {
	return &m.FindSecretsConfig
}

func (m *AWSFindSecretsModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	c := m.FindSecretsConfig
	if c.DBPath == "" {
		c.DBPath = secrets.DefaultDBPath(c.OutputDir)
	}

	var s secrets.SecretScanner
	if err := s.Start(c.DBPath); err != nil {
		return fmt.Errorf("failed to create Titus scanner: %w", err)
	}
	defer func() {
		if closeErr := s.Close(); closeErr != nil {
			slog.Warn("failed to close Titus scanner", "error", closeErr)
		}
	}()

	inputs, err := m.collectInputs()
	if err != nil {
		return fmt.Errorf("failed to collect inputs: %v", err)
	}

	lister := cclist.NewCloudControlLister(c.AWSCommonRecon)
	inputPipeline := pipeline.From(inputs...)
	listed := pipeline.New[output.AWSResource]()
	pipeline.Pipe(inputPipeline, lister.List, listed)

	extractor := extraction.NewAWSExtractor(c.AWSCommonRecon, extraction.Config{
		MaxEvents:  c.MaxEvents,
		MaxStreams: c.MaxStreams,
	})

	extracted := pipeline.New[output.ScanInput]()
	pipeline.Pipe(listed, extractor.Extract, extracted)

	scanned := pipeline.New[secrets.SecretScanResult]()
	pipeline.Pipe(extracted, s.Scan, scanned)
	pipeline.Pipe(scanned, riskFromScanResult, out)

	return out.Wait()
}

func (m *AWSFindSecretsModule) collectInputs() ([]string, error) {
	if len(m.ResourceARN) > 0 {
		return m.ResourceARN, nil
	}

	resourceTypes, err := resolveRequestedResourceTypes(m.ResourceType, m.SupportedResourceTypes())
	if err != nil {
		return nil, err
	}

	return resourceTypes, nil
}

func riskFromScanResult(result secrets.SecretScanResult, out *pipeline.P[model.AurelianModel]) error {
	proof := buildProofData(result.ResourceRef, result.Match)
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

// extractRuleShortName extracts the short rule identifier from a Titus rule ID.
// For IDs like "np.aws.1", returns "aws". For single-segment IDs, returns the
// full ID lowercased.
func extractRuleShortName(ruleID string) string {
	parts := strings.Split(ruleID, ".")
	if len(parts) >= 2 {
		return parts[1]
	}
	return strings.ToLower(ruleID)
}

func formatSecretRiskName(ruleID string) string {
	return fmt.Sprintf("aws-secret-%s", extractRuleShortName(ruleID))
}

func riskSeverityFromMatch(match *types.Match) output.RiskSeverity {
	if match.ValidationResult != nil && match.ValidationResult.Status == types.StatusValid {
		return output.RiskSeverityHigh
	}
	return output.RiskSeverityMedium
}

// buildProofData constructs proof JSON matching Guard's secrets proof format.
// Includes provenance with cloud resource context so the UI can render findings.
func buildProofData(resourceRef string, match *types.Match) map[string]interface{} {
	proof := map[string]interface{}{
		"finding_id":   match.FindingID,
		"rule_name":    match.RuleName,
		"rule_text_id": match.RuleID,
		"resource_ref": resourceRef,
		"num_matches":  1,
		"matches": []map[string]interface{}{
			{
				"provenance": []map[string]interface{}{
					{
						"kind":        "cloud_resource",
						"platform":    "aws",
						"resource_id": resourceRef,
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
