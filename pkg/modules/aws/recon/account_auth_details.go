package recon

import (
	"github.com/praetorian-inc/aurelian/pkg/aws/gaad"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&AWSAccountAuthDetailsModule{})
}

// AccountAuthDetailsConfig holds the typed parameters for account-auth-details module.
type AccountAuthDetailsConfig struct {
	plugin.AWSReconBase
}

// AWSAccountAuthDetailsModule retrieves IAM account authorization details
type AWSAccountAuthDetailsModule struct {
	config AccountAuthDetailsConfig
}

func (m *AWSAccountAuthDetailsModule) ID() string                { return "account-auth-details" }
func (m *AWSAccountAuthDetailsModule) Name() string              { return "AWS Get Account Authorization Details" }
func (m *AWSAccountAuthDetailsModule) Platform() plugin.Platform { return plugin.PlatformAWS }
func (m *AWSAccountAuthDetailsModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *AWSAccountAuthDetailsModule) OpsecLevel() string        { return "moderate" }
func (m *AWSAccountAuthDetailsModule) Authors() []string         { return []string{"Praetorian"} }

func (m *AWSAccountAuthDetailsModule) Description() string {
	return "Retrieves IAM account authorization details including users, roles, groups, and policies. " +
		"IAM is a global service, so this module always queries us-east-1 region."
}

func (m *AWSAccountAuthDetailsModule) References() []string {
	return []string{
		"https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html",
	}
}

func (m *AWSAccountAuthDetailsModule) SupportedResourceTypes() []string {
	return []string{
		"AWS::IAM::User",
		"AWS::IAM::Role",
		"AWS::IAM::Group",
		"AWS::IAM::Policy",
	}
}

func (m *AWSAccountAuthDetailsModule) Parameters() any {
	return &m.config
}

func (m *AWSAccountAuthDetailsModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
	c := m.config

	// Delegate to shared GAAD package
	result, accountID, err := gaad.GetAccountAuthorizationDetails(cfg.Context, c.AWSReconBase)
	if err != nil {
		return nil, err
	}

	return []plugin.Result{
		{
			Data: result,
			Metadata: map[string]any{
				"module":    m.ID(),
				"platform":  m.Platform(),
				"accountID": accountID,
				"region":    "us-east-1",
			},
		},
	}, nil
}
