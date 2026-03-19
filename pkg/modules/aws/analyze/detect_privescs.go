package analyze

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j/dbtype"
	privesc "github.com/praetorian-inc/aurelian/pkg/graph/queries/enrich/aws/privesc_new"
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
	Queryer privesc.Queryer `param:"-"`
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
	queryer, err := m.resolveQueryer()
	if err != nil {
		return err
	}
	defer queryer.Close()

	ctx := context.Background()
	for _, method := range allMethods() {
		if err := runMethod(ctx, queryer, method, out); err != nil {
			slog.Warn("privesc method failed", "id", method.ID(), "error", err)
		}
	}
	return nil
}

// resolveQueryer returns the caller-provided Queryer if set,
// otherwise creates a default Neo4jQueryer using GraphOutputBase params.
func (m *DetectPrivescsModule) resolveQueryer() (privesc.Queryer, error) {
	if m.Queryer != nil {
		return m.Queryer, nil
	}
	q := privesc.NewNeo4jQueryer()
	if err := q.Connect(m.Neo4jURI, m.Neo4jUsername, m.Neo4jPassword); err != nil {
		return nil, fmt.Errorf("connecting to Neo4j: %w", err)
	}
	return q, nil
}

func allMethods() []privesc.AWSPrivesc {
	return []privesc.AWSPrivesc{
		privesc.NewMethod01IAMCreatePolicyVersion(),
		privesc.NewMethod02IAMSetDefaultPolicyVersion(),
		privesc.NewMethod03IAMCreateAccessKey(),
	}
}

func runMethod(
	ctx context.Context,
	queryer privesc.Queryer,
	method privesc.AWSPrivesc,
	out *pipeline.P[model.AurelianModel],
) error {
	slog.Debug("running privesc query", "id", method.ID())

	result, err := queryer.Query(ctx, method.Query())
	if err != nil {
		return fmt.Errorf("executing %s: %w", method.ID(), err)
	}

	for _, record := range result.Records {
		risk, err := recordToRisk(method, record)
		if err != nil {
			slog.Warn("skipping record", "method", method.ID(), "error", err)
			continue
		}
		out.Send(risk)
	}
	return nil
}

func recordToRisk(method privesc.AWSPrivesc, record map[string]interface{}) (output.AurelianRisk, error) {
	pathData, ok := record["path"]
	if !ok {
		return output.AurelianRisk{}, fmt.Errorf("record missing 'path' column")
	}

	cleanPath := pathToMap(pathData)

	contextBytes, err := json.Marshal(cleanPath)
	if err != nil {
		return output.AurelianRisk{}, fmt.Errorf("marshalling path context: %w", err)
	}

	dedupHash := fmt.Sprintf("%x", sha256.Sum256(contextBytes))

	return output.AurelianRisk{
		Name:            method.Name(),
		Severity:        output.NormalizeSeverity(method.Severity()),
		DeduplicationID: dedupHash,
		Context:         contextBytes,
	}, nil
}

// pathToMap converts a Neo4j dbtype.Path into a clean, driver-independent
// representation suitable for JSON serialization and stable deduplication.
func pathToMap(raw interface{}) map[string]interface{} {
	path, ok := raw.(dbtype.Path)
	if !ok {
		return map[string]interface{}{"raw": raw}
	}

	nodes := make([]map[string]interface{}, len(path.Nodes))
	for i, n := range path.Nodes {
		nodes[i] = map[string]interface{}{
			"labels":     n.Labels,
			"properties": n.Props,
		}
	}

	rels := make([]map[string]interface{}, len(path.Relationships))
	for i, r := range path.Relationships {
		rels[i] = map[string]interface{}{
			"type":       r.Type,
			"properties": r.Props,
		}
	}

	return map[string]interface{}{
		"nodes":         nodes,
		"relationships": rels,
	}
}
