package analyze

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	privesc "github.com/praetorian-inc/aurelian/pkg/graph/queries/dsl"
	privesc2 "github.com/praetorian-inc/aurelian/pkg/graph/queries/enrich/aws/privesc"
	"log/slog"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&DetectPrivescsModule{})
}

// DetectPrivescsConfig holds parameters for the detect-privescs module.
type DetectPrivescsConfig struct {
	plugin.GraphOutputBase
}

// SetQueryer allows external callers (e.g. Guard) to inject a Queryer.
func (c *DetectPrivescsConfig) SetQueryer(q privesc.Queryer) {
	c.Queryer = q
}

// DetectPrivescsModule runs all privesc method queries against a Neo4j graph
// and emits an AurelianRisk for each detected privilege escalation path.
type DetectPrivescsModule struct {
	DetectPrivescsConfig
}

func (m *DetectPrivescsModule) ID() string                       { return "detect-privescs" }
func (m *DetectPrivescsModule) Name() string                     { return "AWS Detect Privilege Escalation" }
func (m *DetectPrivescsModule) Platform() plugin.Platform        { return plugin.PlatformAWS }
func (m *DetectPrivescsModule) Category() plugin.Category        { return plugin.CategoryAnalyze }
func (m *DetectPrivescsModule) OpsecLevel() string               { return "none" }
func (m *DetectPrivescsModule) Authors() []string                { return []string{"Praetorian"} }
func (m *DetectPrivescsModule) References() []string             { return nil }
func (m *DetectPrivescsModule) SupportedResourceTypes() []string { return nil }
func (m *DetectPrivescsModule) Parameters() any                  { return &m.DetectPrivescsConfig }

func (m *DetectPrivescsModule) Description() string {
	return "Runs privilege escalation detection queries against a Neo4j IAM graph " +
		"and emits risks for each detected escalation path."
}

func (m *DetectPrivescsModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	defer m.Queryer.Close()

	ctx := context.Background()
	for _, method := range privesc2.AllPrivescQueries {
		if err := m.runMethod(ctx, method, out); err != nil {
			slog.Warn("privesc method failed", "id", method.ID(), "error", err)
		}
	}
	return nil
}

func (m *DetectPrivescsModule) runMethod(
	ctx context.Context,
	method privesc2.AWSPrivesc,
	out *pipeline.P[model.AurelianModel],
) error {
	slog.Debug("running privesc query", "id", method.ID())

	paths, err := m.Queryer.Query(ctx, method.Query())
	if err != nil {
		return fmt.Errorf("executing %s: %w", method.ID(), err)
	}

	slog.Info("finished query", "id", method.ID(), "count", len(paths))

	for _, path := range paths {
		risk, err := m.matchedPathToRisk(method, path)
		if err != nil {
			slog.Warn("skipping path", "method", method.ID(), "error", err)
			continue
		}
		out.Send(risk)
	}
	return nil
}

func (m *DetectPrivescsModule) matchedPathToRisk(method privesc2.AWSPrivesc, path privesc.MatchedPath) (output.AurelianRisk, error) {
	contextBytes, err := json.Marshal(path.Hops)
	if err != nil {
		return output.AurelianRisk{}, fmt.Errorf("marshalling match context: %w", err)
	}

	dedupHash := fmt.Sprintf("%x", sha256.Sum256(contextBytes))

	return output.AurelianRisk{
		Name:            method.Name(),
		Severity:        output.NormalizeSeverity(method.Severity()),
		DeduplicationID: dedupHash,
		Context:         contextBytes,
	}, nil
}
