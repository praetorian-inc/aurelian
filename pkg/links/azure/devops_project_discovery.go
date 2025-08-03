package azure

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/message"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// AzureDevOpsProjectDiscoveryLink discovers projects in an Azure DevOps organization
type AzureDevOpsProjectDiscoveryLink struct {
	*chain.Base
}

func NewAzureDevOpsProjectDiscoveryLink(configs ...cfg.Config) chain.Link {
	l := &AzureDevOpsProjectDiscoveryLink{}
	l.Base = chain.NewBase(l, configs...)
	return l
}

func (l *AzureDevOpsProjectDiscoveryLink) Params() []cfg.Param {
	return []cfg.Param{
		options.AzureDevOpsPAT(),
		options.AzureDevOpsProject(),
	}
}

// makeDevOpsRequest helper function for authenticated API calls
func (l *AzureDevOpsProjectDiscoveryLink) makeDevOpsRequest(method, url string) (*http.Response, error) {
	pat, _ := cfg.As[string](l.Arg("devops-pat"))

	req, err := http.NewRequestWithContext(l.Context(), method, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add PAT authentication
	auth := base64.StdEncoding.EncodeToString([]byte(":" + pat))
	req.Header.Set("Authorization", "Basic "+auth)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	l.Logger.Debug("Making Azure DevOps API request", "method", method, "url", url)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("unauthorized access - please verify your PAT token has the required permissions")
	}

	return resp, nil
}

func (l *AzureDevOpsProjectDiscoveryLink) Process(config types.DevOpsScanConfig) error {
	specificProject, _ := cfg.As[string](l.Arg("devops-project"))

	// If a specific project is requested, use it directly
	if specificProject != "" {
		config.Project = specificProject
		l.Send(config)
		return nil
	}

	// Otherwise, discover all projects in the organization
	projectsUrl := fmt.Sprintf("https://dev.azure.com/%s/_apis/projects?api-version=7.1-preview.1", config.Organization)

	projectsResp, err := l.makeDevOpsRequest(http.MethodGet, projectsUrl)
	if err != nil {
		return fmt.Errorf("failed to get projects: %w", err)
	}
	defer projectsResp.Body.Close()

	var projectsResult struct {
		Count int `json:"count"`
		Value []struct {
			Name string `json:"name"`
		} `json:"value"`
	}

	if err := json.NewDecoder(projectsResp.Body).Decode(&projectsResult); err != nil {
		return fmt.Errorf("failed to parse projects response: %w", err)
	}

	message.Info("Found %d projects in organization %s", projectsResult.Count, config.Organization)

	// Send a config for each project
	for _, project := range projectsResult.Value {
		projectConfig := types.DevOpsScanConfig{
			Organization: config.Organization,
			Project:      project.Name,
		}

		l.Logger.Debug("Discovered project", "project", project.Name, "organization", config.Organization)
		l.Send(projectConfig)
	}

	return nil
}
