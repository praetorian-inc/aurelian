package azure

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/message"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// AzureDevOpsVariableGroupsLink scans variable groups for secrets
type AzureDevOpsVariableGroupsLink struct {
	*chain.Base
}

func NewAzureDevOpsVariableGroupsLink(configs ...cfg.Config) chain.Link {
	l := &AzureDevOpsVariableGroupsLink{}
	l.Base = chain.NewBase(l, configs...)
	return l
}

func (l *AzureDevOpsVariableGroupsLink) Params() []cfg.Param {
	return []cfg.Param{
		options.AzureDevOpsPAT(),
	}
}

// makeDevOpsRequest helper function for authenticated API calls
func (l *AzureDevOpsVariableGroupsLink) makeDevOpsRequest(method, url string) (*http.Response, error) {
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
		return nil, fmt.Errorf("unauthorized access - please verify your PAT token has Variable Groups (Read) permissions")
	}

	return resp, nil
}

func (l *AzureDevOpsVariableGroupsLink) Process(config types.DevOpsScanConfig) error {
	// Get variable groups for the project
	groupsUrl := fmt.Sprintf("https://dev.azure.com/%s/%s/_apis/distributedtask/variablegroups?api-version=7.1-preview.2",
		config.Organization, config.Project)

	groupsResp, err := l.makeDevOpsRequest(http.MethodGet, groupsUrl)
	if err != nil {
		return fmt.Errorf("failed to get variable groups: %w", err)
	}
	defer groupsResp.Body.Close()

	var groupsResult struct {
		Value []struct {
			Id        int    `json:"id"`
			Name      string `json:"name"`
			Variables map[string]struct {
				IsSecret bool   `json:"isSecret"`
				Value    string `json:"value"`
			} `json:"variables"`
		} `json:"value"`
	}

	body, err := io.ReadAll(groupsResp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if err := json.Unmarshal(body, &groupsResult); err != nil {
		return fmt.Errorf("failed to parse groups response: %w", err)
	}

	if len(groupsResult.Value) == 0 {
		l.Logger.Info("No variable groups found in project", "project", config.Project)
		return nil
	}

	message.Info("Found %d variable groups to scan in project %s", len(groupsResult.Value), config.Project)

	for _, group := range groupsResult.Value {
		// Create content for scanning (exclude marked secrets to reduce noise)
		vars := make(map[string]string)
		secretCount := 0
		for k, v := range group.Variables {
			if !v.IsSecret {
				vars[k] = v.Value
			} else {
				secretCount++
			}
		}

		l.Logger.Debug("Processing variable group",
			"id", group.Id,
			"name", group.Name,
			"total_vars", len(group.Variables),
			"secret_vars", secretCount)

		content, _ := json.Marshal(vars)

		npInput := types.NpInput{
			Content: string(content),
			Provenance: types.NpProvenance{
				Platform:     "azure-devops",
				ResourceType: "Microsoft.DevOps/VariableGroups",
				ResourceID: fmt.Sprintf("%s/%s/variablegroup/%d",
					config.Organization, config.Project, group.Id),
				AccountID: config.Organization,
			},
		}

		l.Send(npInput)
	}

	return nil
}
