package recon

import (
	"github.com/praetorian-inc/aurelian/pkg/aws/iam/orgpolicies"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&AWSOrgPoliciesModule{})
}

type OrgPoliciesConfig struct {
	plugin.AWSReconBase
}

type AWSOrgPoliciesModule struct {
	config OrgPoliciesConfig
}

func (m *AWSOrgPoliciesModule) ID() string                { return "org-policies" }
func (m *AWSOrgPoliciesModule) Name() string              { return "AWS Organization Policies" }
func (m *AWSOrgPoliciesModule) Platform() plugin.Platform { return plugin.PlatformAWS }
func (m *AWSOrgPoliciesModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *AWSOrgPoliciesModule) OpsecLevel() string        { return "moderate" }
func (m *AWSOrgPoliciesModule) Authors() []string         { return []string{"Praetorian"} }

func (m *AWSOrgPoliciesModule) Description() string {
	return "Collects AWS Organizations service control policies (SCPs) and resource control policies (RCPs), " +
		"including the organizational hierarchy and policy-to-target mappings."
}

func (m *AWSOrgPoliciesModule) References() []string {
	return []string{
		"https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html",
		"https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html",
	}
}

func (m *AWSOrgPoliciesModule) SupportedResourceTypes() []string {
	return []string{
		"AWS::Organizations::Policy",
		"AWS::Organizations::OrganizationalUnit",
		"AWS::Organizations::Account",
	}
}

func (m *AWSOrgPoliciesModule) Parameters() any {
	return &m.config
}

func (m *AWSOrgPoliciesModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
	c := m.config

	orgPols, err := orgpolicies.CollectOrgPolicies(cfg.Context, orgpolicies.CollectorOptions{
		Profile:    c.Profile,
		ProfileDir: c.ProfileDir,
	})
	if err != nil {
		return nil, err
	}

	return []plugin.Result{
		{
			Data: orgPols,
			Metadata: map[string]any{
				"module":   m.ID(),
				"platform": m.Platform(),
			},
		},
	}, nil
}
