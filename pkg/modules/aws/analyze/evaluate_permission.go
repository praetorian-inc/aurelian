package analyze

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/praetorian-inc/aurelian/pkg/aws/iam/orgpolicies"
	"github.com/praetorian-inc/aurelian/pkg/escalation/subprocess"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

func init() {
	plugin.Register(&EvaluatePermissionModule{})
}

type EvaluatePermissionConfig struct {
	Serve           bool   `param:"serve" desc:"Run as subprocess evaluator (stdin/stdout JSON protocol)" default:"false"`
	GAADDir         string `param:"gaad-dir" desc:"Directory containing cached GAAD JSON file" required:""`
	OrgPoliciesFile string `param:"org-policies-file" desc:"Path to Org Policies JSON file"`
}

type EvaluatePermissionModule struct {
	EvaluatePermissionConfig
}

func (m *EvaluatePermissionModule) ID() string                { return "evaluate-permission" }
func (m *EvaluatePermissionModule) Name() string              { return "AWS Evaluate Permission" }
func (m *EvaluatePermissionModule) Platform() plugin.Platform { return plugin.PlatformAWS }
func (m *EvaluatePermissionModule) Category() plugin.Category { return plugin.CategoryAnalyze }
func (m *EvaluatePermissionModule) OpsecLevel() string        { return "none" }
func (m *EvaluatePermissionModule) Authors() []string         { return []string{"Praetorian"} }

func (m *EvaluatePermissionModule) Description() string {
	return "Subprocess IAM permission evaluator for the escalation-solver. " +
		"Reads cached GAAD data and answers permission queries via stdin/stdout JSON protocol."
}

func (m *EvaluatePermissionModule) References() []string {
	return []string{}
}

func (m *EvaluatePermissionModule) SupportedResourceTypes() []string { return nil }

func (m *EvaluatePermissionModule) Parameters() any {
	return &m.EvaluatePermissionConfig
}

func (m *EvaluatePermissionModule) Run(cfg plugin.Config, _ *pipeline.P[model.AurelianModel]) error {
	if !m.Serve {
		return fmt.Errorf("--serve is required (this module runs as a subprocess evaluator)")
	}

	cfg.Info("loading GAAD data from %s", m.GAADDir)
	gaad, err := loadGAAD(m.GAADDir)
	if err != nil {
		return fmt.Errorf("loading GAAD: %w", err)
	}
	cfg.Success("GAAD loaded (account: %s, users: %d, roles: %d)",
		gaad.AccountID, gaad.Users.Len(), gaad.Roles.Len())

	var orgPolicies *orgpolicies.OrgPolicies
	if m.OrgPoliciesFile != "" {
		data, err := os.ReadFile(m.OrgPoliciesFile)
		if err != nil {
			return fmt.Errorf("reading org policies: %w", err)
		}
		orgPolicies = &orgpolicies.OrgPolicies{}
		if err := json.Unmarshal(data, orgPolicies); err != nil {
			return fmt.Errorf("parsing org policies: %w", err)
		}
	}

	eval := subprocess.NewEvaluator(gaad, orgPolicies, nil)
	cfg.Info("starting subprocess evaluator (stdin/stdout)")
	return subprocess.Serve(os.Stdin, os.Stdout, eval)
}

// loadGAAD reads the GAAD JSON file from the directory.
func loadGAAD(dir string) (*types.AuthorizationAccountDetails, error) {
	// Look for gaad.json or account-authorization-details.json.
	candidates := []string{
		filepath.Join(dir, "gaad.json"),
		filepath.Join(dir, "account-authorization-details.json"),
	}

	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var gaad types.AuthorizationAccountDetails
		if err := json.Unmarshal(data, &gaad); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", path, err)
		}
		return &gaad, nil
	}

	return nil, fmt.Errorf("no GAAD file found in %s (expected gaad.json or account-authorization-details.json)", dir)
}
