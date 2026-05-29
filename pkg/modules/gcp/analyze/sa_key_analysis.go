package analyze

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&GCPSAKeyAnalysisModule{})
}

type SAKeyAnalysisConfig struct {
	KeyFile string `param:"key-file" desc:"Path to GCP service account key JSON file" required:"true" shortcode:"k"`
}

type GCPSAKeyAnalysisModule struct {
	SAKeyAnalysisConfig
}

func (m *GCPSAKeyAnalysisModule) ID() string                { return "sa-key-analysis" }
func (m *GCPSAKeyAnalysisModule) Name() string              { return "GCP Service Account Key Analysis" }
func (m *GCPSAKeyAnalysisModule) Platform() plugin.Platform { return plugin.PlatformGCP }
func (m *GCPSAKeyAnalysisModule) Category() plugin.Category { return plugin.CategoryAnalyze }
func (m *GCPSAKeyAnalysisModule) OpsecLevel() string        { return "safe" }
func (m *GCPSAKeyAnalysisModule) Authors() []string         { return []string{"Praetorian"} }
func (m *GCPSAKeyAnalysisModule) Description() string {
	return "Extract metadata from a GCP service account key JSON file without making any API calls. Reveals project ID, service account email, and key ID."
}
func (m *GCPSAKeyAnalysisModule) References() []string {
	return []string{"https://cloud.google.com/iam/docs/keys-create-delete"}
}
func (m *GCPSAKeyAnalysisModule) SupportedResourceTypes() []string { return nil }
func (m *GCPSAKeyAnalysisModule) Parameters() any                  { return &m.SAKeyAnalysisConfig }

func (m *GCPSAKeyAnalysisModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	keyData, err := readKeyFile(m.KeyFile)
	if err != nil {
		return fmt.Errorf("reading key file: %w", err)
	}

	saName := saNameFromEmail(keyData.ClientEmail)

	cfg.Success("project: %s", keyData.ProjectID)
	cfg.Success("email: %s", keyData.ClientEmail)
	cfg.Success("key ID: %s", keyData.PrivateKeyID)
	cfg.Success("SA name: %s", saName)

	resultsJSON, _ := json.Marshal(keyData)
	out.Send(output.AnalyzeResult{
		Module:  m.ID(),
		Input:   m.KeyFile,
		Results: json.RawMessage(resultsJSON),
	})
	return nil
}

type saKeyJSON struct {
	Type         string `json:"type"`
	ProjectID    string `json:"project_id"`
	PrivateKeyID string `json:"private_key_id"`
	ClientEmail  string `json:"client_email"`
	ClientID     string `json:"client_id"`
	AuthURI      string `json:"auth_uri"`
	TokenURI     string `json:"token_uri"`
}

func readKeyFile(path string) (*saKeyJSON, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}
	var key saKeyJSON
	if err := json.Unmarshal(data, &key); err != nil {
		return nil, fmt.Errorf("parsing JSON: %w", err)
	}
	if key.Type == "" || key.ClientEmail == "" {
		return nil, fmt.Errorf("missing required fields (type, client_email)")
	}
	return &key, nil
}

func saNameFromEmail(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}
