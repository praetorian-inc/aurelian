package azure

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/praetorian-inc/aurelian/pkg/links/azure/base"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// AzureDevOpsAuthLink handles authentication and validates PAT token permissions
type AzureDevOpsAuthLink struct {
	*base.NativeAzureLink
}

func NewAzureDevOpsAuthLink(args map[string]any) *AzureDevOpsAuthLink {
	return &AzureDevOpsAuthLink{
		NativeAzureLink: base.NewNativeAzureLink("devops-auth", args),
	}
}

func (l *AzureDevOpsAuthLink) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		{Name: "devops-pat", Type: "string", Required: true, Description: "Azure DevOps Personal Access Token"},
		{Name: "devops-org", Type: "string", Required: true, Description: "Azure DevOps organization name"},
	}
}

func (l *AzureDevOpsAuthLink) Process(ctx context.Context, input any) ([]any, error) {
	pat := l.ArgString("devops-pat", "")
	organization := l.ArgString("devops-org", "")

	if pat == "" {
		return nil, fmt.Errorf("Azure DevOps PAT is required")
	}

	if organization == "" {
		return nil, fmt.Errorf("Azure DevOps organization is required")
	}

	// Test authentication by making a simple API call
	testUrl := fmt.Sprintf("https://dev.azure.com/%s/_apis/projects?api-version=7.1-preview.1", organization)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, testUrl, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth test request: %w", err)
	}

	// Add PAT authentication
	auth := base64.StdEncoding.EncodeToString([]byte(":" + pat))
	req.Header.Set("Authorization", "Basic "+auth)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to test authentication: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("unauthorized access - please verify your PAT token has the required permissions")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authentication test failed with status %d", resp.StatusCode)
	}

	l.Logger().Info("Successfully authenticated to Azure DevOps", "organization", organization)

	// Pass the authenticated config to the next link
	config := types.DevOpsScanConfig{
		Organization: organization,
		Project:      "", // Will be set by project discovery link
	}

	l.Send(config)
	return l.Outputs(), nil
}
