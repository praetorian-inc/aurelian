package analyze

import (
	"encoding/json"
	"fmt"

	"github.com/praetorian-inc/aurelian/pkg/aws/iam"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&ExpandActionsModule{})
}

type ExpandActionsConfig struct {
	Action string `param:"action" desc:"IAM action pattern to expand (supports wildcards, e.g. s3:Get* or *)" required:"true"`
}

type ExpandActionsModule struct {
	ExpandActionsConfig
}

func (m *ExpandActionsModule) ID() string                { return "expand-actions" }
func (m *ExpandActionsModule) Name() string              { return "AWS Expand IAM Actions" }
func (m *ExpandActionsModule) Platform() plugin.Platform { return plugin.PlatformAWS }
func (m *ExpandActionsModule) Category() plugin.Category { return plugin.CategoryAnalyze }
func (m *ExpandActionsModule) OpsecLevel() string        { return "safe" }
func (m *ExpandActionsModule) Authors() []string         { return []string{"Praetorian"} }
func (m *ExpandActionsModule) Parameters() any           { return &m.ExpandActionsConfig }

func (m *ExpandActionsModule) Description() string {
	return "Expands wildcard IAM action patterns (e.g. s3:Get* or *) into the full list of matching AWS actions " +
		"by fetching the AWS Policy Generator service map."
}

func (m *ExpandActionsModule) References() []string {
	return []string{"https://awspolicygen.s3.amazonaws.com/js/policies.js"}
}

func (m *ExpandActionsModule) SupportedResourceTypes() []string {
	return nil
}

func (m *ExpandActionsModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	c := m.ExpandActionsConfig

	expander := &iam.ActionExpander{}
	matches, err := expander.Expand(c.Action)
	if err != nil {
		return fmt.Errorf("expanding action pattern %q: %w", c.Action, err)
	}

	cfg.Info("expanded %q to %d matching actions", c.Action, len(matches))

	resultsJSON, err := json.Marshal(matches)
	if err != nil {
		return fmt.Errorf("marshaling results: %w", err)
	}

	out.Send(output.AnalyzeResult{
		Module:  m.ID(),
		Input:   c.Action,
		Results: json.RawMessage(resultsJSON),
	})

	return nil
}
