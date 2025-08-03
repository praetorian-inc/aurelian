package azure

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/message"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// AzureDevOpsServiceEndpointsLink scans service endpoints for secrets
type AzureDevOpsServiceEndpointsLink struct {
	*chain.Base
}

func NewAzureDevOpsServiceEndpointsLink(configs ...cfg.Config) chain.Link {
	l := &AzureDevOpsServiceEndpointsLink{}
	l.Base = chain.NewBase(l, configs...)
	return l
}

func (l *AzureDevOpsServiceEndpointsLink) Params() []cfg.Param {
	return []cfg.Param{
		options.AzureDevOpsPAT(),
	}
}

// makeDevOpsRequest helper function for authenticated API calls
func (l *AzureDevOpsServiceEndpointsLink) makeDevOpsRequest(method, url string) (*http.Response, error) {
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

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("unauthorized access - please verify your PAT token has Service Connections (Read) permissions")
	}

	return resp, nil
}

func (l *AzureDevOpsServiceEndpointsLink) Process(config types.DevOpsScanConfig) error {
	// Get service endpoints for the project
	endpointsUrl := fmt.Sprintf("https://dev.azure.com/%s/%s/_apis/serviceendpoint/endpoints?api-version=7.1-preview.4",
		config.Organization, config.Project)

	endpointsResp, err := l.makeDevOpsRequest(http.MethodGet, endpointsUrl)
	if err != nil {
		return fmt.Errorf("failed to get service endpoints: %w", err)
	}
	defer endpointsResp.Body.Close()

	var endpointsResult struct {
		Value []struct {
			Id          string                 `json:"id"`
			Name        string                 `json:"name"`
			Type        string                 `json:"type"`
			Description string                 `json:"description"`
			Url         string                 `json:"url"`
			Data        map[string]interface{} `json:"data"`
		} `json:"value"`
	}

	body, err := io.ReadAll(endpointsResp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if err := json.Unmarshal(body, &endpointsResult); err != nil {
		return fmt.Errorf("failed to parse endpoints response: %w", err)
	}

	if len(endpointsResult.Value) == 0 {
		l.Logger.Info("No service endpoints found in project", "project", config.Project)
		return nil
	}

	message.Info("Found %d service endpoints to scan in project %s", len(endpointsResult.Value), config.Project)

	for _, endpoint := range endpointsResult.Value {
		// Filter out sensitive fields to reduce noise while preserving potential secrets
		cleanedData := make(map[string]interface{})
		for k, v := range endpoint.Data {
			keyLower := strings.ToLower(k)
			if !strings.Contains(keyLower, "password") &&
				!strings.Contains(keyLower, "secret") &&
				!strings.Contains(keyLower, "key") &&
				!strings.Contains(keyLower, "token") {
				cleanedData[k] = v
			}
		}

		// Create endpoint content for scanning
		endpointContent := struct {
			Id          string                 `json:"id"`
			Name        string                 `json:"name"`
			Type        string                 `json:"type"`
			Description string                 `json:"description"`
			Url         string                 `json:"url"`
			Data        map[string]interface{} `json:"data"`
		}{
			Id:          endpoint.Id,
			Name:        endpoint.Name,
			Type:        endpoint.Type,
			Description: endpoint.Description,
			Url:         endpoint.Url,
			Data:        cleanedData,
		}

		content, err := json.Marshal(endpointContent)
		if err != nil {
			l.Logger.Error("Failed to marshal endpoint content", "error", err.Error(), "endpoint_id", endpoint.Id)
			continue
		}

		// Send endpoint content for scanning
		npInput := types.NpInput{
			Content: string(content),
			Provenance: types.NpProvenance{
				Platform:     "azure-devops",
				ResourceType: "Microsoft.DevOps/ServiceEndpoints",
				ResourceID: fmt.Sprintf("%s/%s/serviceendpoint/%s",
					config.Organization, config.Project, endpoint.Id),
				AccountID: config.Organization,
			},
		}
		l.Send(npInput)

		// Get endpoint execution history
		historyUrl := fmt.Sprintf("https://dev.azure.com/%s/%s/_apis/serviceendpoint/%s/executionhistory?api-version=7.1-preview.1",
			config.Organization, config.Project, endpoint.Id)

		historyResp, err := l.makeDevOpsRequest(http.MethodGet, historyUrl)
		if err != nil {
			l.Logger.Error("Failed to get endpoint history", "error", err.Error(), "endpoint_id", endpoint.Id)
			continue
		}

		historyBody, err := io.ReadAll(historyResp.Body)
		historyResp.Body.Close()
		if err == nil {
			// Send endpoint history for scanning
			historyInput := types.NpInput{
				Content: string(historyBody),
				Provenance: types.NpProvenance{
					Platform:     "azure-devops",
					ResourceType: "Microsoft.DevOps/ServiceEndpoints/History",
					ResourceID: fmt.Sprintf("%s/%s/serviceendpoint/%s/history",
						config.Organization, config.Project, endpoint.Id),
					AccountID: config.Organization,
				},
			}
			l.Send(historyInput)
		}
	}

	return nil
}
