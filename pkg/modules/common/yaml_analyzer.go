package common

import (
	"fmt"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

// YAMLAnalyzer is a generic analyzer module that evaluates YAML rules.
type YAMLAnalyzer struct {
	rules []YAMLRule
}

// NewYAMLAnalyzer creates an analyzer with the given rules.
func NewYAMLAnalyzer(rules []YAMLRule) *YAMLAnalyzer {
	return &YAMLAnalyzer{rules: rules}
}

// Module interface implementation
func (m *YAMLAnalyzer) ID() string   { return "yaml-analyzer" }
func (m *YAMLAnalyzer) Name() string { return "YAML Rule Analyzer" }
func (m *YAMLAnalyzer) Description() string {
	return "Evaluates declarative YAML rules against AWSResource properties"
}
func (m *YAMLAnalyzer) Platform() plugin.Platform { return plugin.Platform("any") }
func (m *YAMLAnalyzer) Category() plugin.Category { return plugin.CategoryAnalyze }
func (m *YAMLAnalyzer) OpsecLevel() string        { return "passive" }
func (m *YAMLAnalyzer) Authors() []string         { return []string{"Praetorian"} }
func (m *YAMLAnalyzer) References() []string      { return []string{} }
func (m *YAMLAnalyzer) Parameters() any           { return nil }

// Run evaluates all rules against the provided resource.
func (m *YAMLAnalyzer) Run(cfg plugin.Config, out func(models ...model.AurelianModel)) error {
	// Extract resource from config
	resourceAny, ok := cfg.Args["resource"]
	if !ok {
		return fmt.Errorf("resource not provided in config")
	}

	resource, ok := resourceAny.(output.AWSResource)
	if !ok {
		return fmt.Errorf("resource is not an AWSResource")
	}

	// Evaluate all rules against the resource
	var findings []plugin.Finding
	for _, rule := range m.rules {
		// Skip rules that don't apply to this resource type
		if rule.ResourceType != resource.ResourceType {
			continue
		}

		// Check if all match conditions are true
		if MatchAll(rule.Match, resource.Properties) {
			findings = append(findings, plugin.Finding{
				RuleID:         rule.ID,
				Severity:       rule.Severity,
				Name:           rule.Name,
				Description:    rule.Description,
				Resource:       resource,
				References:     rule.References,
				Recommendation: rule.Recommendation,
			})
		}
	}

	for _, f := range findings {
		out(f)
	}
	return nil
}
