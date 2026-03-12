package analyze

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

const (
	awsPolicyGenURL = "https://awspolicygen.s3.amazonaws.com/js/policies.js"
	policyJSPrefix  = "app.PolicyEditorConfig="
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

func (m *ExpandActionsModule) Description() string {
	return "Expands wildcard IAM action patterns (e.g. s3:Get* or *) into the full list of matching AWS actions " +
		"by fetching the AWS Policy Generator service map."
}

func (m *ExpandActionsModule) References() []string {
	return []string{}
}

func (m *ExpandActionsModule) SupportedResourceTypes() []string {
	return nil
}

func (m *ExpandActionsModule) Parameters() any {
	return &m.ExpandActionsConfig
}

func (m *ExpandActionsModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	c := m.ExpandActionsConfig

	cfg.Log.Info("fetching AWS policy generator service map")

	actions, err := fetchAllAWSActions()
	if err != nil {
		return fmt.Errorf("fetching AWS actions: %w", err)
	}

	cfg.Log.Info("fetched %d actions, expanding pattern: %s", len(actions), c.Action)

	matches, err := expandActionPattern(c.Action, actions)
	if err != nil {
		return fmt.Errorf("expanding action pattern: %w", err)
	}

	cfg.Log.Info("found %d matching actions", len(matches))

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

// fetchAllAWSActions fetches the AWS policy generator JS file and returns all known IAM actions.
// NOTE: pkg/aws/iam/action_expander.go contains similar logic; tracked for future deduplication.
func fetchAllAWSActions() ([]string, error) {
	resp, err := http.Get(awsPolicyGenURL) //nolint:noctx
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", awsPolicyGenURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", awsPolicyGenURL, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	// Strip the JS assignment prefix to get raw JSON.
	raw := strings.TrimPrefix(string(body), policyJSPrefix)

	var config struct {
		ServiceMap map[string]struct {
			StringPrefix string   `json:"StringPrefix"`
			Actions      []string `json:"Actions"`
		} `json:"serviceMap"`
	}

	if err := json.Unmarshal([]byte(raw), &config); err != nil {
		return nil, fmt.Errorf("parsing policy config JSON: %w", err)
	}

	var actions []string
	for _, svc := range config.ServiceMap {
		for _, action := range svc.Actions {
			actions = append(actions, svc.StringPrefix+":"+action)
		}
	}

	return actions, nil
}

// expandActionPattern matches IAM action strings against a wildcard pattern.
// The pattern supports '*' as a wildcard (e.g. "s3:Get*", "*").
func expandActionPattern(pattern string, actions []string) ([]string, error) {
	if pattern == "*" {
		result := make([]string, len(actions))
		copy(result, actions)
		return result, nil
	}

	// Convert glob-style pattern to regex: escape everything, then replace \* with .*
	escaped := regexp.QuoteMeta(pattern)
	escaped = strings.ReplaceAll(escaped, `\*`, `.*`)
	re, err := regexp.Compile("(?i)^" + escaped + "$")
	if err != nil {
		return nil, fmt.Errorf("compiling pattern %q: %w", pattern, err)
	}

	var matches []string
	for _, action := range actions {
		if re.MatchString(action) {
			matches = append(matches, action)
		}
	}

	return matches, nil
}
