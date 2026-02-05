package azure

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/praetorian-inc/aurelian/internal/message"
	"github.com/praetorian-inc/aurelian/pkg/links/azure/base"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// AzureDevOpsProjectDiscoveryLink discovers projects in an Azure DevOps organization
type AzureDevOpsProjectDiscoveryLink struct {
	*base.NativeAzureLink
}

func NewAzureDevOpsProjectDiscoveryLink(args map[string]any) *AzureDevOpsProjectDiscoveryLink {
	return &AzureDevOpsProjectDiscoveryLink{
		NativeAzureLink: base.NewNativeAzureLink("devops-project-discovery", args),
	}
}

func (l *AzureDevOpsProjectDiscoveryLink) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		{Name: "devops-pat", Type: "string", Required: true, Description: "Azure DevOps Personal Access Token"},
		{Name: "devops-project", Type: "string", Required: false, Description: "Specific project to scan (optional, discovers all if not provided)"},
	}
}

// makeDevOpsRequest helper function for authenticated API calls
func (l *AzureDevOpsProjectDiscoveryLink) makeDevOpsRequest(ctx context.Context, method, url string, pat string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add PAT authentication
	auth := base64.StdEncoding.EncodeToString([]byte(":" + pat))
	req.Header.Set("Authorization", "Basic "+auth)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	l.Logger().Debug("Making Azure DevOps API request", "method", method, "url", url)

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

func (l *AzureDevOpsProjectDiscoveryLink) Process(ctx context.Context, input any) ([]any, error) {
	config, ok := input.(types.DevOpsScanConfig)
	if !ok {
		return nil, fmt.Errorf("expected DevOpsScanConfig, got %T", input)
	}

	pat := l.ArgString("devops-pat", "")
	specificProject := l.ArgString("devops-project", "")

	// If a specific project is requested, use it directly
	if specificProject != "" {
		config.Project = specificProject
		l.Send(config)
		return l.Outputs(), nil
	}

	// Otherwise, discover all projects in the organization
	projectsUrl := fmt.Sprintf("https://dev.azure.com/%s/_apis/projects?api-version=7.1-preview.1", config.Organization)

	projectsResp, err := l.makeDevOpsRequest(ctx, http.MethodGet, projectsUrl, pat)
	if err != nil {
		return nil, fmt.Errorf("failed to get projects: %w", err)
	}
	defer projectsResp.Body.Close()

	var projectsResult struct {
		Count int `json:"count"`
		Value []struct {
			Name string `json:"name"`
		} `json:"value"`
	}

	if err := json.NewDecoder(projectsResp.Body).Decode(&projectsResult); err != nil {
		return nil, fmt.Errorf("failed to parse projects response: %w", err)
	}

	message.Info("Found %d projects in organization %s", projectsResult.Count, config.Organization)

	// Send a config for each project
	for _, project := range projectsResult.Value {
		projectConfig := types.DevOpsScanConfig{
			Organization: config.Organization,
			Project:      project.Name,
		}

		l.Logger().Debug("Discovered project", "project", project.Name, "organization", config.Organization)
		l.Send(projectConfig)
	}

	return l.Outputs(), nil
}
