package analyze

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"google.golang.org/api/option"

	"github.com/praetorian-inc/aurelian/pkg/gcp/iam"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&ExpandPermissionsModule{})
}

// ExpandPermissionsConfig holds the parameters for the expand-permissions module.
type ExpandPermissionsConfig struct {
	Roles           string `param:"roles" desc:"Comma-separated GCP role names (e.g. roles/editor,roles/storage.admin)" required:"true"`
	CredentialsFile string `param:"creds-file" desc:"Path to GCP credentials JSON"`
	QuotaProject    string `param:"quota-project" desc:"GCP project for API quota and billing (required for WIF credentials)"`
}

// ExpandPermissionsModule resolves GCP IAM roles to the full set of
// permissions they grant.
type ExpandPermissionsModule struct {
	ExpandPermissionsConfig
}

func (m *ExpandPermissionsModule) ID() string                { return "expand-permissions" }
func (m *ExpandPermissionsModule) Name() string              { return "GCP Expand Permissions" }
func (m *ExpandPermissionsModule) Platform() plugin.Platform { return plugin.PlatformGCP }
func (m *ExpandPermissionsModule) Category() plugin.Category { return plugin.CategoryAnalyze }
func (m *ExpandPermissionsModule) OpsecLevel() string        { return "safe" }
func (m *ExpandPermissionsModule) Authors() []string         { return []string{"Praetorian"} }
func (m *ExpandPermissionsModule) Parameters() any           { return &m.ExpandPermissionsConfig }

func (m *ExpandPermissionsModule) Description() string {
	return "Expands GCP IAM role names into the full list of permissions they include " +
		"by querying the IAM predefined roles API."
}

func (m *ExpandPermissionsModule) References() []string {
	return []string{"https://cloud.google.com/iam/docs/understanding-roles"}
}

func (m *ExpandPermissionsModule) SupportedResourceTypes() []string {
	return nil
}

func (m *ExpandPermissionsModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	c := m.ExpandPermissionsConfig

	roles := strings.Split(c.Roles, ",")
	for i := range roles {
		roles[i] = strings.TrimSpace(roles[i])
	}

	var clientOptions []option.ClientOption
	if c.CredentialsFile != "" {
		clientOptions = append(clientOptions, option.WithCredentialsFile(c.CredentialsFile)) //nolint:staticcheck
	}
	if c.QuotaProject != "" {
		clientOptions = append(clientOptions, option.WithQuotaProject(c.QuotaProject))
	}

	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}

	expander := &iam.RoleExpander{}
	expander.SetClientOptions(clientOptions...)
	permissions, err := expander.Expand(ctx, roles)
	if err != nil {
		return fmt.Errorf("expanding roles %q: %w", c.Roles, err)
	}

	cfg.Info("expanded %q to %d permissions", c.Roles, len(permissions))

	resultsJSON, err := json.Marshal(permissions)
	if err != nil {
		return fmt.Errorf("marshaling results: %w", err)
	}

	out.Send(output.AnalyzeResult{
		Module:  m.ID(),
		Input:   c.Roles,
		Results: json.RawMessage(resultsJSON),
	})

	return nil
}
