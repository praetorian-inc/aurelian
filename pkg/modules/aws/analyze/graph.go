package analyze

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/graph"
	"github.com/praetorian-inc/aurelian/pkg/graph/adapters"
	"github.com/praetorian-inc/aurelian/pkg/graph/queries"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&AWSGraphAnalyzeModule{})
}

const privescRiskName = "aws-privesc-path"

type GraphAnalyzeConfig struct {
	plugin.GraphOutputBase
}

// AWSGraphAnalyzeModule reads a seeded+enriched Neo4j graph and surfaces
// privilege-escalation paths (from aws/analysis/privesc_paths) as AurelianRisk
// findings. It composes with `aurelian aws recon graph --neo4j-uri …`, which
// populates the graph this module analyzes.
type AWSGraphAnalyzeModule struct {
	GraphAnalyzeConfig
}

func (m *AWSGraphAnalyzeModule) ID() string                { return "graph" }
func (m *AWSGraphAnalyzeModule) Name() string              { return "AWS Graph Privesc Path Analysis" }
func (m *AWSGraphAnalyzeModule) Platform() plugin.Platform { return plugin.PlatformAWS }
func (m *AWSGraphAnalyzeModule) Category() plugin.Category { return plugin.CategoryAnalyze }
func (m *AWSGraphAnalyzeModule) OpsecLevel() string        { return "safe" }
func (m *AWSGraphAnalyzeModule) Authors() []string         { return []string{"Praetorian"} }

func (m *AWSGraphAnalyzeModule) Description() string {
	return "Analyzes a Neo4j graph populated by `aws recon graph --neo4j-uri` and surfaces " +
		"privilege-escalation paths (non-admin principal → admin target) as risk findings. " +
		"Requires --neo4j-uri pointing at the seeded graph."
}

func (m *AWSGraphAnalyzeModule) References() []string {
	return []string{
		"https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html",
	}
}

func (m *AWSGraphAnalyzeModule) SupportedResourceTypes() []string {
	return []string{
		"AWS::IAM::User",
		"AWS::IAM::Role",
		"AWS::IAM::Group",
		"AWS::IAM::Policy",
	}
}

func (m *AWSGraphAnalyzeModule) Parameters() any {
	return &m.GraphAnalyzeConfig
}

func (m *AWSGraphAnalyzeModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	if m.Neo4jURI == "" {
		return fmt.Errorf("--neo4j-uri is required: the graph is the input source for this analysis")
	}

	dbCfg := graph.NewConfig(m.Neo4jURI, m.Neo4jUsername, m.Neo4jPassword)
	db, err := adapters.NewNeo4jAdapter(dbCfg)
	if err != nil {
		return fmt.Errorf("creating Neo4j adapter: %w", err)
	}
	defer func() { _ = db.Close() }()
	if err := db.VerifyConnectivity(cfg.Context); err != nil {
		return fmt.Errorf("Neo4j connection failed: %w", err)
	}

	// Enrichment is idempotent (MERGE/SET), so running it here makes the module
	// robust against a graph that was seeded but not yet enriched.
	if err := queries.EnrichAWS(cfg.Context, db); err != nil {
		return fmt.Errorf("running enrichment queries: %w", err)
	}

	result, err := queries.RunPlatformQuery(cfg.Context, db, "aws/analysis/privesc_paths", nil)
	if err != nil {
		return fmt.Errorf("running privesc-paths analysis: %w", err)
	}

	for _, rec := range result.Records {
		risk, ok := riskFromRecord(rec)
		if !ok {
			continue
		}
		out.Send(risk)
	}
	return nil
}

// riskFromRecord maps one aws/analysis/privesc_paths row to an AurelianRisk.
// It returns ok=false for malformed rows (missing/empty attacker ARN or methods)
// rather than emitting a meaningless finding.
func riskFromRecord(rec map[string]any) (output.AurelianRisk, bool) {
	attackerARN, _ := rec["attacker_arn"].(string)
	targetARN, _ := rec["target_arn"].(string)
	if attackerARN == "" || targetARN == "" {
		return output.AurelianRisk{}, false
	}

	methods := toStringSlice(rec["methods"])
	if len(methods) == 0 {
		// Production recon always stamps a method on CAN_PRIVESC edges, so an
		// empty methods list points at a hand-seeded graph; log the drop with the
		// path endpoints to aid diagnosis. Behavior (drop) is unchanged.
		slog.Warn("dropping privesc path with no decoded methods",
			"attacker_arn", attackerARN, "target_arn", targetARN)
		return output.AurelianRisk{}, false
	}
	severities := toStringSlice(rec["method_severities"])
	hopCount := toInt64(rec["hop_count"])

	pathSeverity := maxSeverity(severities)

	context, err := json.Marshal(struct {
		AttackerARN  string   `json:"attacker_arn"`
		TargetARN    string   `json:"target_arn"`
		Methods      []string `json:"methods"`
		HopCount     int64    `json:"hop_count"`
		PathSeverity string   `json:"path_severity"`
	}{
		AttackerARN:  attackerARN,
		TargetARN:    targetARN,
		Methods:      methods,
		HopCount:     hopCount,
		PathSeverity: string(pathSeverity),
	})
	if err != nil {
		return output.AurelianRisk{}, false
	}

	return output.AurelianRisk{
		Name:               privescRiskName,
		Severity:           pathSeverity,
		ImpactedResourceID: attackerARN,
		DeduplicationID:    attackerARN + "|" + targetARN + "|" + strings.Join(methods, ">"),
		Context:            context,
	}, true
}

// maxSeverity returns the highest severity in the list using low<medium<high.
// The privesc_paths query's WHERE clause already requires an admin target, so
// an empty/unknown severity list defaults to high rather than info.
func maxSeverity(severities []string) output.RiskSeverity {
	rank := map[output.RiskSeverity]int{
		output.RiskSeverityLow:    1,
		output.RiskSeverityMedium: 2,
		output.RiskSeverityHigh:   3,
	}
	best := output.RiskSeverityHigh
	bestRank := 0
	for _, s := range severities {
		norm := output.NormalizeSeverity(output.RiskSeverity(s))
		if r := rank[norm]; r > bestRank {
			bestRank = r
			best = norm
		}
	}
	return best
}

// toStringSlice coerces a Neo4j list column (decoded as []interface{} of string)
// into a []string, skipping any non-string elements.
func toStringSlice(v any) []string {
	raw, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, e := range raw {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// toInt64 coerces a Neo4j numeric column (int64 from the driver, float64 after a
// JSON round-trip) into an int64.
func toInt64(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case int:
		return int64(n)
	case float64:
		return int64(n)
	}
	return 0
}
