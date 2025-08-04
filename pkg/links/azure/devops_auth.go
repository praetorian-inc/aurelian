package azure

import (
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// AzureDevOpsAuthLink handles authentication and validates PAT token permissions
type AzureDevOpsAuthLink struct {
	*chain.Base
}

func NewAzureDevOpsAuthLink(configs ...cfg.Config) chain.Link {
	l := &AzureDevOpsAuthLink{}
	l.Base = chain.NewBase(l, configs...)
	return l
}

func (l *AzureDevOpsAuthLink) Params() []cfg.Param {
	return []cfg.Param{
		options.AzureDevOpsPAT(),
		options.AzureDevOpsOrganization(),
	}
}

func (l *AzureDevOpsAuthLink) Process(input any) error {
	pat, _ := cfg.As[string](l.Arg("devops-pat"))
	organization, _ := cfg.As[string](l.Arg("devops-org"))

	if pat == "" {
		return fmt.Errorf("Azure DevOps PAT is required")
	}

	if organization == "" {
		return fmt.Errorf("Azure DevOps organization is required")
	}

	// Test authentication by making a simple API call
	testUrl := fmt.Sprintf("https://dev.azure.com/%s/_apis/projects?api-version=7.1-preview.1", organization)

	req, err := http.NewRequestWithContext(l.Context(), http.MethodGet, testUrl, nil)
	if err != nil {
		return fmt.Errorf("failed to create auth test request: %w", err)
	}

	// Add PAT authentication
	auth := base64.StdEncoding.EncodeToString([]byte(":" + pat))
	req.Header.Set("Authorization", "Basic "+auth)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to test authentication: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("unauthorized access - please verify your PAT token has the required permissions")
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("authentication test failed with status %d", resp.StatusCode)
	}

	l.Logger.Info("Successfully authenticated to Azure DevOps", "organization", organization)

	// Pass the authenticated config to the next link
	config := types.DevOpsScanConfig{
		Organization: organization,
		Project:      "", // Will be set by project discovery link
	}

	l.Send(config)
	return nil
}
