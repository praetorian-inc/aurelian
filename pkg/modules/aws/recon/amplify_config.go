package recon

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/aws/amplify"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&AmplifyConfigModule{})
}

type AmplifyConfigParams struct {
	URL      string `param:"url" desc:"Amplify app URL to analyze" required:"true" shortcode:"u"`
	Validate bool   `param:"validate" desc:"Validate extracted API keys and probe endpoints for auth requirements" shortcode:"v"`
}

type AmplifyConfigModule struct {
	AmplifyConfigParams
}

func (m *AmplifyConfigModule) ID() string                       { return "amplify-config" }
func (m *AmplifyConfigModule) Name() string                     { return "AWS Amplify Config Extractor" }
func (m *AmplifyConfigModule) Platform() plugin.Platform        { return plugin.PlatformAWS }
func (m *AmplifyConfigModule) Category() plugin.Category        { return plugin.CategoryRecon }
func (m *AmplifyConfigModule) OpsecLevel() string               { return "safe" }
func (m *AmplifyConfigModule) Authors() []string                { return []string{"Praetorian"} }
func (m *AmplifyConfigModule) SupportedResourceTypes() []string { return nil }
func (m *AmplifyConfigModule) Parameters() any                  { return &m.AmplifyConfigParams }

func (m *AmplifyConfigModule) Description() string {
	return "Extracts AWS Amplify configuration from a web application by scanning HTML and JavaScript " +
		"bundles for Cognito, AppSync, API Gateway, S3, and other AWS service details."
}

func (m *AmplifyConfigModule) References() []string {
	return []string{
		"https://docs.amplify.aws/gen1/javascript/tools/libraries/configure-categories/",
	}
}

func (m *AmplifyConfigModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	target := strings.TrimSpace(m.URL)
	if target == "" {
		return fmt.Errorf("url is required")
	}

	ext := amplify.NewExtractor()

	ctx := cfg.Context
	cfg.Info("extracting amplify config from %s", target)
	result, err := ext.Extract(ctx, target)
	if err != nil {
		cfg.Warn("extracting amplify config: %s", err)
		return nil
	}

	resultsJSON, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("marshaling results: %w", err)
	}
	out.Send(output.AnalyzeResult{
		Module:  m.ID(),
		Input:   target,
		Results: json.RawMessage(resultsJSON),
	})

	cfg.Success("amplify configuration for %s", result.URL)
	for _, line := range amplify.FormatConfig(result) {
		cfg.Info("%s", line)
	}
	if len(result.CognitoSignupAttributes) > 0 {
		cfg.Success("cognito sign-up is configured — self-registration may be enabled")
	}

	if m.Validate {
		for _, v := range ext.Validate(ctx, result) {
			switch {
			case v.Open || v.Valid:
				cfg.Success("  [%s] %s — %s", v.Type, v.Target, v.Message)
			case v.StatusCode == 0:
				cfg.Warn("  [%s] %s — %s", v.Type, v.Target, v.Message)
			default:
				cfg.Info("  [%s] %s — %s", v.Type, v.Target, v.Message)
			}
		}
	}

	return nil
}
