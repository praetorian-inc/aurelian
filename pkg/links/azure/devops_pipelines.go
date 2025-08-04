package azure

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	jtypes "github.com/praetorian-inc/janus-framework/pkg/types"
	"github.com/praetorian-inc/nebula/internal/message"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// AzureDevOpsPipelinesLink scans pipelines, their definitions, runs, and logs
type AzureDevOpsPipelinesLink struct {
	*chain.Base
}

func NewAzureDevOpsPipelinesLink(configs ...cfg.Config) chain.Link {
	l := &AzureDevOpsPipelinesLink{}
	l.Base = chain.NewBase(l, configs...)
	return l
}

func (l *AzureDevOpsPipelinesLink) Params() []cfg.Param {
	return []cfg.Param{
		options.AzureDevOpsPAT(),
	}
}

// makeDevOpsRequest helper function for authenticated API calls
func (l *AzureDevOpsPipelinesLink) makeDevOpsRequest(method, url string) (*http.Response, error) {
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
		return nil, fmt.Errorf("unauthorized access - please verify your PAT token has Build (Read) permissions")
	}

	return resp, nil
}

// processPipelineRunLogs processes pipeline run logs for secret scanning
func (l *AzureDevOpsPipelinesLink) processPipelineRunLogs(config types.DevOpsScanConfig, pipelineId int, runId int) error {
	logsUrl := fmt.Sprintf("https://dev.azure.com/%s/%s/_apis/pipelines/%d/runs/%d/logs?api-version=7.1-preview.1",
		config.Organization, config.Project, pipelineId, runId)

	logsResp, err := l.makeDevOpsRequest(http.MethodGet, logsUrl)
	if err != nil {
		return fmt.Errorf("failed to get logs: %w", err)
	}
	defer logsResp.Body.Close()

	var logsList struct {
		Value []struct {
			Id        int    `json:"id"`
			LineCount int    `json:"lineCount"`
			Url       string `json:"url"`
		} `json:"value"`
	}

	if err := json.NewDecoder(logsResp.Body).Decode(&logsList); err != nil {
		return fmt.Errorf("failed to parse logs list: %w", err)
	}

	// Process each log file
	for _, log := range logsList.Value {
		if log.LineCount == 0 {
			continue // Skip empty logs
		}

		logContentUrl := fmt.Sprintf("https://dev.azure.com/%s/%s/_apis/pipelines/%d/runs/%d/logs/%d?api-version=7.1-preview.1",
			config.Organization, config.Project, pipelineId, runId, log.Id)

		logContentResp, err := l.makeDevOpsRequest(http.MethodGet, logContentUrl)
		if err != nil {
			l.Logger.Error("Failed to get log content", "error", err.Error(), "log_id", log.Id)
			continue
		}

		logContent, err := io.ReadAll(logContentResp.Body)
		logContentResp.Body.Close()
		if err != nil {
			l.Logger.Error("Failed to read log content", "error", err.Error())
			continue
		}

		npInput := jtypes.NPInput{
			Content: string(logContent),
			Provenance: jtypes.NPProvenance{
				Platform:     "azure-devops",
				ResourceType: "Microsoft.DevOps/Pipelines/Runs/Logs",
				ResourceID: fmt.Sprintf("%s/%s/pipeline/%d/run/%d/log/%d",
					config.Organization, config.Project, pipelineId, runId, log.Id),
				AccountID: config.Organization,
			},
		}

		l.Send(npInput)
	}

	return nil
}

func (l *AzureDevOpsPipelinesLink) Process(input any) error {
	// Handle both DevOpsScanConfig and NPInput types
	var config types.DevOpsScanConfig
	switch v := input.(type) {
	case types.DevOpsScanConfig:
		config = v
	case jtypes.NPInput:
		// Skip NPInput - we only process DevOpsScanConfig for pipeline discovery
		l.Logger.Debug("Skipping NPInput in pipelines link", "resource_id", v.Provenance.ResourceID)
		l.Send(input) // Pass through to next link
		return nil
	default:
		return fmt.Errorf("unsupported input type: %T", input)
	}
	// Get list of pipelines in the project
	pipelinesUrl := fmt.Sprintf("https://dev.azure.com/%s/%s/_apis/pipelines?api-version=7.1-preview.1",
		config.Organization, config.Project)

	pipelinesResp, err := l.makeDevOpsRequest(http.MethodGet, pipelinesUrl)
	if err != nil {
		return fmt.Errorf("failed to get pipelines: %w", err)
	}
	defer pipelinesResp.Body.Close()

	var pipelinesResult struct {
		Value []struct {
			Id     int    `json:"id"`
			Name   string `json:"name"`
			Folder string `json:"folder"`
		} `json:"value"`
	}

	body, err := io.ReadAll(pipelinesResp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if err := json.Unmarshal(body, &pipelinesResult); err != nil {
		return fmt.Errorf("failed to parse pipelines response: %w", err)
	}

	if len(pipelinesResult.Value) == 0 {
		l.Logger.Info("No pipelines found in project", "project", config.Project)
		return nil
	}

	message.Info("Found %d pipelines to scan in project %s", len(pipelinesResult.Value), config.Project)

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 5) // Limit concurrent requests

	for _, pipeline := range pipelinesResult.Value {
		wg.Add(1)
		go func(pipeline types.DevOpsPipeline) {
			defer wg.Done()
			semaphore <- struct{}{}        // Acquire
			defer func() { <-semaphore }() // Release

			// Get pipeline definition
			defUrl := fmt.Sprintf("https://dev.azure.com/%s/%s/_apis/pipelines/%d?api-version=7.1-preview.1",
				config.Organization, config.Project, pipeline.Id)

			defResp, err := l.makeDevOpsRequest(http.MethodGet, defUrl)
			if err != nil {
				l.Logger.Error("Failed to get pipeline definition", "error", err.Error(), "pipeline_id", pipeline.Id)
				return
			}
			defer defResp.Body.Close()

			defBody, err := io.ReadAll(defResp.Body)
			if err != nil {
				l.Logger.Error("Failed to read definition", "error", err.Error())
				return
			}

			// Send pipeline definition for scanning
			npInput := jtypes.NPInput{
				Content: string(defBody),
				Provenance: jtypes.NPProvenance{
					Platform:     "azure-devops",
					ResourceType: "Microsoft.DevOps/Pipelines/Definition",
					ResourceID: fmt.Sprintf("%s/%s/pipeline/%d",
						config.Organization, config.Project, pipeline.Id),
					AccountID: config.Organization,
				},
			}
			l.Send(npInput)

			// Get recent runs
			runsUrl := fmt.Sprintf("https://dev.azure.com/%s/%s/_apis/pipelines/%d/runs?api-version=7.1-preview.1",
				config.Organization, config.Project, pipeline.Id)

			runsResp, err := l.makeDevOpsRequest(http.MethodGet, runsUrl)
			if err != nil {
				l.Logger.Error("Failed to get pipeline runs", "error", err.Error(), "pipeline_id", pipeline.Id)
				return
			}
			defer runsResp.Body.Close()

			var runsResult struct {
				Value []struct {
					Id        int               `json:"id"`
					Variables map[string]string `json:"variables"`
				} `json:"value"`
			}

			runsBody, _ := io.ReadAll(runsResp.Body)
			if err := json.Unmarshal(runsBody, &runsResult); err != nil {
				l.Logger.Error("Failed to parse runs", "error", err.Error())
				return
			}

			// Process each run's data
			for _, run := range runsResult.Value {
				// Send run variables for scanning
				if len(run.Variables) > 0 {
					varsJson, _ := json.Marshal(run.Variables)
					npInput := jtypes.NPInput{
						Content: string(varsJson),
						Provenance: jtypes.NPProvenance{
							Platform:     "azure-devops",
							ResourceType: "Microsoft.DevOps/Pipelines/Runs/Variables",
							ResourceID: fmt.Sprintf("%s/%s/pipeline/%d/run/%d/variables",
								config.Organization, config.Project, pipeline.Id, run.Id),
							AccountID: config.Organization,
						},
					}
					l.Send(npInput)
				}

				// Process run logs
				if err := l.processPipelineRunLogs(config, pipeline.Id, run.Id); err != nil {
					l.Logger.Error("Failed to process run logs", "error", err.Error(), "run_id", run.Id)
				}
			}
		}(types.DevOpsPipeline{
			Id:     pipeline.Id,
			Name:   pipeline.Name,
			Folder: pipeline.Folder,
		})
	}

	wg.Wait()
	return nil
}
