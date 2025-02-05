package stages

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/internal/message"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/types"
)

func isUnauthorizedResponse(resp *http.Response) bool {
	return resp != nil && resp.StatusCode == http.StatusUnauthorized
}

// Helper function to make authenticated requests to Azure DevOps API
func makeDevOpsRequest(ctx context.Context, logger *slog.Logger, method string, url string, pat string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	// Add PAT authentication
	auth := base64.StdEncoding.EncodeToString([]byte(":" + pat))
	req.Header.Set("Authorization", "Basic "+auth)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	logger.Debug("Making Azure DevOps API request",
		slog.String("method", method),
		slog.String("url", url))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if isUnauthorizedResponse(resp) {
		return nil, fmt.Errorf("unauthorized access - please verify your PAT token has the required permissions")
	}

	return resp, nil
}

// Helper function to scan a Git repository with NoseyParker
func scanGitRepo(ctx context.Context, logger *slog.Logger, opts []*types.Option, repoPath string) error {
	// Prepare NoseyParker command
	datastorePath := filepath.Join(
		options.GetOptionByName(options.OutputOpt.Name, opts).Value,
		options.GetOptionByName(options.NoseyParkerOutputOpt.Name, opts).Value,
	)

	npPath := options.GetOptionByName(options.NoseyParkerPathOpt.Name, opts).Value
	npArgs := []string{
		"scan",
		"-d", datastorePath,
		"--git-history", "full",
		repoPath,
	}

	// Add any custom args
	customArgs := options.GetOptionByName(options.NoseyParkerArgsOpt.Name, opts).Value
	if customArgs != "" {
		npArgs = append(npArgs, strings.Split(customArgs, " ")...)
	}

	logger.Debug("Running NoseyParker scan",
		slog.String("command", npPath),
		slog.Any("args", npArgs),
		slog.String("repo", repoPath))

	cmd := exec.CommandContext(ctx, npPath, npArgs...)
	if output, err := cmd.CombinedOutput(); err != nil {
		logger.Error("NoseyParker scan failed",
			slog.String("repo", repoPath),
			slog.String("error", err.Error()),
			slog.String("output", string(output)))
		return err
	}

	return nil
}

// Handles cloning and preparing a Git repository for scanning
func prepareGitRepo(ctx context.Context, logger *slog.Logger, pat string, cloneUrl string, repoPath string) error {
	if err := os.MkdirAll(filepath.Dir(repoPath), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}

	message.Info("Cloning repository %s", cloneUrl)
	logger.Debug("Cloning repository",
		slog.String("url", cloneUrl),
		slog.String("path", repoPath))

	// Clone with full history using --mirror
	cmd := exec.CommandContext(ctx, "git", "clone", "--mirror", cloneUrl, repoPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to clone repository: %v\nOutput: %s", err, output)
	}

	return nil
}

// Handles scanning pipeline jobs and their outputs
func processPipelineJob(ctx context.Context, logger *slog.Logger, pat string, job *types.DevOpsPipelineJob, config types.DevOpsScanConfig, out chan<- types.NpInput) {
	// Get job timeline data
	timelineUrl := fmt.Sprintf("https://dev.azure.com/%s/%s/_apis/build/builds/%d/timeline?api-version=7.1-preview.2",
		config.Organization,
		config.Project,
		job.Id)

	timelineResp, err := makeDevOpsRequest(ctx, logger, http.MethodGet, timelineUrl, pat)

	if err != nil {
		if strings.Contains(err.Error(), "unauthorized access") {
			logger.Error("Unauthorized access to repositories - verify PAT has Code (Read) permissions")
		} else {
			logger.Error("Failed to get job timeline",
				slog.String("error", err.Error()),
				slog.Int("job_id", job.Id))
		}
		return
	}

	defer timelineResp.Body.Close()

	timelineBody, err := io.ReadAll(timelineResp.Body)
	if err != nil {
		logger.Error("Failed to read timeline response",
			slog.String("error", err.Error()),
			slog.Int("job_id", job.Id))
		return
	}

	// Send timeline data for scanning
	out <- types.NpInput{
		Content: string(timelineBody),
		Provenance: types.NpProvenance{
			Platform:     "azure-devops",
			ResourceType: "Microsoft.DevOps/Pipelines/Jobs/Timeline",
			ResourceID: fmt.Sprintf("%s/%s/jobs/%d/timeline",
				config.Organization, config.Project, job.Id),
			AccountID: config.Organization,
		},
	}

	// Get job variables
	if len(job.Variables) > 0 {
		varsContent, err := json.Marshal(job.Variables)
		if err == nil {
			out <- types.NpInput{
				Content: string(varsContent),
				Provenance: types.NpProvenance{
					Platform:     "azure-devops",
					ResourceType: "Microsoft.DevOps/Pipelines/Jobs/Variables",
					ResourceID: fmt.Sprintf("%s/%s/jobs/%d/variables",
						config.Organization, config.Project, job.Id),
					AccountID: config.Organization,
				},
			}
		}
	}

	// Get job outputs
	outputsUrl := fmt.Sprintf("https://dev.azure.com/%s/%s/_apis/build/builds/%d/artifacts?api-version=7.1-preview.1",
		config.Organization,
		config.Project,
		job.Id)

	outputsResp, err := makeDevOpsRequest(ctx, logger, http.MethodGet, outputsUrl, pat)
	if err != nil {
		if strings.Contains(err.Error(), "unauthorized access") {
			logger.Error("Unauthorized access to job outputs - verify PAT has Code (Read) permissions")
		} else {
			logger.Error("Failed to get job outputs", slog.String("error", err.Error()))
		}
		return
	}
	defer outputsResp.Body.Close()

	outputsBody, err := io.ReadAll(outputsResp.Body)
	if err == nil {
		out <- types.NpInput{
			Content: string(outputsBody),
			Provenance: types.NpProvenance{
				Platform:     "azure-devops",
				ResourceType: "Microsoft.DevOps/Pipelines/Jobs/Outputs",
				ResourceID: fmt.Sprintf("%s/%s/jobs/%d/outputs",
					config.Organization, config.Project, job.Id),
				AccountID: config.Organization,
			},
		}
	}
}

// List all projects in an organization
func GetOrganizationProjects(ctx context.Context, logger *slog.Logger, pat string, organization string) ([]string, error) {
	projectsUrl := fmt.Sprintf("https://dev.azure.com/%s/_apis/projects?api-version=7.1-preview.1", organization)

	projectsResp, err := makeDevOpsRequest(ctx, logger, http.MethodGet, projectsUrl, pat)
	if err != nil {
		if strings.Contains(err.Error(), "unauthorized access") {
			return nil, fmt.Errorf("unauthorized access to projects - verify PAT has Project (Read) permissions")
		}
		return nil, err
	}
	defer projectsResp.Body.Close()

	var projectsResult struct {
		Count int `json:"count"`
		Value []struct {
			Name string `json:"name"`
		} `json:"value"`
	}

	if err := json.NewDecoder(projectsResp.Body).Decode(&projectsResult); err != nil {
		return nil, err
	}

	var projects []string
	for _, project := range projectsResult.Value {
		projects = append(projects, project.Name)
	}

	return projects, nil
}

// AzureDevOpsReposStage handles cloning and scanning Git repositories
func AzureDevOpsReposStage(ctx context.Context, opts []*types.Option, in <-chan string) <-chan types.NpInput {
	logger := logs.NewStageLogger(ctx, opts, "AzureDevOpsReposStage")
	out := make(chan types.NpInput)

	go func() {
		defer close(out)

		for configStr := range in {
			var config types.DevOpsScanConfig
			if err := json.Unmarshal([]byte(configStr), &config); err != nil {
				logger.Error("Failed to parse config", slog.String("error", err.Error()))
				continue
			}

			pat := options.GetOptionByName(options.AzureDevOpsPATOpt.Name, opts).Value
			if pat == "" {
				logger.Error("Azure DevOps PAT is required")
				return
			}

			// List repositories
			reposUrl := fmt.Sprintf("https://dev.azure.com/%s/%s/_apis/git/repositories?api-version=7.1-preview.1",
				config.Organization, config.Project)

			reposResp, err := makeDevOpsRequest(ctx, logger, http.MethodGet, reposUrl, pat)

			if err != nil {
				if strings.Contains(err.Error(), "unauthorized access") {
					logger.Error("Unauthorized access to repositories - verify PAT has Code (Read) permissions")
				} else {
					logger.Error("Failed to get repositories", slog.String("error", err.Error()))
				}
				continue
			}
			defer reposResp.Body.Close()

			body, err := io.ReadAll(reposResp.Body)
			if err != nil {
				logger.Error("Failed to read response", slog.String("error", err.Error()))
				continue
			}

			var reposResult struct {
				Count int `json:"count"`
				Value []struct {
					Id            string `json:"id"`
					Name          string `json:"name"`
					DefaultBranch string `json:"defaultBranch"`
					WebUrl        string `json:"webUrl"`
				} `json:"value"`
			}

			if err := json.Unmarshal(body, &reposResult); err != nil {
				logger.Error("Failed to parse repos response", slog.String("error", err.Error()))
				continue
			}

			message.Info("Found repository to scan %s", reposResult.Value)

			// Process repositories concurrently with rate limiting
			var wg sync.WaitGroup
			semaphore := make(chan struct{}, 5) // Max 5 concurrent operations

			baseDir := filepath.Join(os.TempDir(), fmt.Sprintf("azdo-repos-%s-%s", config.Organization, config.Project))
			defer os.RemoveAll(baseDir)

			for _, repo := range reposResult.Value {
				wg.Add(1)
				go func(repo types.DevOpsRepo) {
					defer wg.Done()
					semaphore <- struct{}{}        // Acquire
					defer func() { <-semaphore }() // Release

					repoDir := filepath.Join(baseDir, repo.Name)
					cloneUrl := fmt.Sprintf("https://%s@dev.azure.com/%s/%s/_git/%s",
						pat,
						url.PathEscape(config.Organization),
						url.PathEscape(config.Project),
						url.PathEscape(repo.Name))

					// Clone and prepare repository
					if err := prepareGitRepo(ctx, logger, pat, cloneUrl, repoDir); err != nil {
						logger.Error("Failed to prepare repository",
							slog.String("repo", repo.Name),
							slog.String("error", err.Error()))

						return
					}

					// Scan with NoseyParker
					if err := scanGitRepo(ctx, logger, opts, repoDir); err != nil {
						logger.Error("Failed to scan repository",
							slog.String("repo", repo.Name),
							slog.String("error", err.Error()))
					}
				}(repo)
			}
			wg.Wait()
		}
	}()
	return out
}

// AzureDevOpsVariableGroupsStage scans variable groups for secrets
func AzureDevOpsVariableGroupsStage(ctx context.Context, opts []*types.Option, in <-chan string) <-chan types.NpInput {
	logger := logs.NewStageLogger(ctx, opts, "AzureDevOpsVariableGroupsStage")
	out := make(chan types.NpInput)

	go func() {
		defer close(out)

		for configStr := range in {
			var config types.DevOpsScanConfig
			if err := json.Unmarshal([]byte(configStr), &config); err != nil {
				logger.Error("Failed to parse config", slog.String("error", err.Error()))
				continue
			}

			pat := options.GetOptionByName(options.AzureDevOpsPATOpt.Name, opts).Value
			if pat == "" {
				logger.Error("Azure DevOps PAT is required")
				return
			}

			// Get variable groups
			groupsUrl := fmt.Sprintf("https://dev.azure.com/%s/%s/_apis/distributedtask/variablegroups?api-version=7.1-preview.2",
				config.Organization, config.Project)

			groupsResp, err := makeDevOpsRequest(ctx, logger, http.MethodGet, groupsUrl, pat)
			if err != nil {
				if strings.Contains(err.Error(), "unauthorized access") {
					logger.Error("Unauthorized access to variable groups - verify PAT has Variable Groups (Read) permissions")
				} else {
					logger.Error("Failed to get variable groups", slog.String("error", err.Error()))
				}
				continue
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
			if err := json.Unmarshal(body, &groupsResult); err != nil {
				logger.Error("Failed to parse groups", slog.String("error", err.Error()))
				continue
			}

			message.Info("Found %d variable groups to scan", len(groupsResult.Value))

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

				logger.Debug("Processing variable group",
					slog.Int("id", group.Id),
					slog.String("name", group.Name),
					slog.Int("total_vars", len(group.Variables)),
					slog.Int("secret_vars", secretCount))

				content, _ := json.Marshal(vars)

				out <- types.NpInput{
					Content: string(content),
					Provenance: types.NpProvenance{
						Platform:     "azure-devops",
						ResourceType: "Microsoft.DevOps/VariableGroups",
						ResourceID: fmt.Sprintf("%s/%s/variablegroup/%d",
							config.Organization, config.Project, group.Id),
						AccountID: config.Organization,
					},
				}
			}
		}
	}()

	return out
}

// AzureDevOpsPipelinesStage scans pipelines, their definitions, and triggers
func AzureDevOpsPipelinesStage(ctx context.Context, opts []*types.Option, in <-chan string) <-chan types.NpInput {
	logger := logs.NewStageLogger(ctx, opts, "AzureDevOpsPipelinesStage")
	out := make(chan types.NpInput)

	go func() {
		defer close(out)

		for configStr := range in {
			var config types.DevOpsScanConfig
			if err := json.Unmarshal([]byte(configStr), &config); err != nil {
				logger.Error("Failed to parse config", slog.String("error", err.Error()))
				continue
			}

			pat := options.GetOptionByName(options.AzureDevOpsPATOpt.Name, opts).Value
			if pat == "" {
				logger.Error("Azure DevOps PAT is required")
				return
			}

			// Get list of pipelines
			pipelinesUrl := fmt.Sprintf("https://dev.azure.com/%s/%s/_apis/pipelines?api-version=7.1-preview.1",
				config.Organization, config.Project)

			pipelinesResp, err := makeDevOpsRequest(ctx, logger, http.MethodGet, pipelinesUrl, pat)
			if err != nil {
				if strings.Contains(err.Error(), "unauthorized access") {
					logger.Error("Unauthorized access to pipelines - verify PAT has Build (Read) permissions")
				} else {
					logger.Error("Failed to get pipelines", slog.String("error", err.Error()))
				}
				continue
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
			if err := json.Unmarshal(body, &pipelinesResult); err != nil {
				logger.Error("Failed to parse pipelines", slog.String("error", err.Error()))
				continue
			}

			message.Info("Found %d pipelines to scan", len(pipelinesResult.Value))

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

					defResp, err := makeDevOpsRequest(ctx, logger, http.MethodGet, defUrl, pat)
					if err != nil {
						if strings.Contains(err.Error(), "unauthorized access") {
							logger.Error("Unauthorized access to pipeline definition - verify PAT has Code (Read) permissions")
						} else {
							logger.Error("Failed to get pipeline definition", slog.String("error", err.Error()))
						}

						return
					}
					defer defResp.Body.Close()

					defBody, err := io.ReadAll(defResp.Body)
					if err != nil {
						logger.Error("Failed to read definition", slog.String("error", err.Error()))
						return
					}

					out <- types.NpInput{
						Content: string(defBody),
						Provenance: types.NpProvenance{
							Platform:     "azure-devops",
							ResourceType: "Microsoft.DevOps/Pipelines/Definition",
							ResourceID: fmt.Sprintf("%s/%s/pipeline/%d",
								config.Organization, config.Project, pipeline.Id),
							AccountID: config.Organization,
						},
					}

					// Get recent runs
					runsUrl := fmt.Sprintf("https://dev.azure.com/%s/%s/_apis/pipelines/%d/runs?api-version=7.1-preview.1",
						config.Organization, config.Project, pipeline.Id)

					runsResp, err := makeDevOpsRequest(ctx, logger, http.MethodGet, runsUrl, pat)
					if err != nil {
						if strings.Contains(err.Error(), "unauthorized access") {
							logger.Error("Unauthorized access to pipeline runs - verify PAT has Code (Read) permissions")
						} else {
							logger.Error("Failed to get pipeline runs", slog.String("error", err.Error()))
						}

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
						logger.Error("Failed to parse runs", slog.String("error", err.Error()))
						return
					}

					// Process each run's data
					for _, run := range runsResult.Value {
						if len(run.Variables) > 0 {
							varsJson, _ := json.Marshal(run.Variables)
							out <- types.NpInput{
								Content: string(varsJson),
								Provenance: types.NpProvenance{
									Platform:     "azure-devops",
									ResourceType: "Microsoft.DevOps/Pipelines/Runs/Variables",
									ResourceID: fmt.Sprintf("%s/%s/pipeline/%d/run/%d/variables",
										config.Organization, config.Project, pipeline.Id, run.Id),
									AccountID: config.Organization,
								},
							}
						}

						// Process run logs
						if err := processPipelineRunLogs(ctx, logger, config, pat, pipeline.Id, run.Id, out); err != nil {
							logger.Error("Failed to process run logs",
								slog.String("error", err.Error()),
								slog.Int("run_id", run.Id))
						}
					}
				}(pipeline)
			}

			wg.Wait()
		}
	}()

	return out
}

func processPipelineRunLogs(ctx context.Context, logger *slog.Logger, config types.DevOpsScanConfig, pat string,
	pipelineId int, runId int, out chan<- types.NpInput) error {

	logsUrl := fmt.Sprintf("https://dev.azure.com/%s/%s/_apis/pipelines/%d/runs/%d/logs?api-version=7.1-preview.1",
		config.Organization, config.Project, pipelineId, runId)

	logsResp, err := makeDevOpsRequest(ctx, logger, http.MethodGet, logsUrl, pat)

	if err != nil {
		if strings.Contains(err.Error(), "unauthorized access") {
			logger.Error("Unauthorized access to logs - verify PAT has Code (Read) permissions")
		} else {
			logger.Error("Failed to get logs", slog.String("error", err.Error()))
		}
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
		return fmt.Errorf("failed to parse logs list: %v", err)
	}

	// Process each log file
	for _, log := range logsList.Value {
		if log.LineCount == 0 {
			continue // Skip empty logs
		}

		logContentUrl := fmt.Sprintf("https://dev.azure.com/%s/%s/_apis/pipelines/%d/runs/%d/logs/%d?api-version=7.1-preview.1",
			config.Organization, config.Project, pipelineId, runId, log.Id)

		logContentResp, err := makeDevOpsRequest(ctx, logger, http.MethodGet, logContentUrl, pat)
		if err != nil {
			if strings.Contains(err.Error(), "unauthorized access") {
				logger.Error("Unauthorized access to log content - verify PAT has Code (Read) permissions")
			} else {
				logger.Error("Failed to get log content",
					slog.String("error", err.Error()),
					slog.Int("log_id", log.Id))
				continue
			}
		}

		logContent, err := io.ReadAll(logContentResp.Body)
		logContentResp.Body.Close()
		if err != nil {
			logger.Error("Failed to read log content", slog.String("error", err.Error()))
			continue
		}

		out <- types.NpInput{
			Content: string(logContent),
			Provenance: types.NpProvenance{
				Platform:     "azure-devops",
				ResourceType: "Microsoft.DevOps/Pipelines/Runs/Logs",
				ResourceID: fmt.Sprintf("%s/%s/pipeline/%d/run/%d/log/%d",
					config.Organization, config.Project, pipelineId, runId, log.Id),
				AccountID: config.Organization,
			},
		}
	}

	return nil
}

// AzureDevOpsServiceEndpointsStage scans service endpoints for secrets
func AzureDevOpsServiceEndpointsStage(ctx context.Context, opts []*types.Option, in <-chan string) <-chan types.NpInput {
	logger := logs.NewStageLogger(ctx, opts, "AzureDevOpsServiceEndpointsStage")
	out := make(chan types.NpInput)

	go func() {
		defer close(out)

		for configStr := range in {
			var config types.DevOpsScanConfig
			if err := json.Unmarshal([]byte(configStr), &config); err != nil {
				logger.Error("Failed to parse config", slog.String("error", err.Error()))
				continue
			}

			pat := options.GetOptionByName(options.AzureDevOpsPATOpt.Name, opts).Value

			// Get service endpoints
			endpointsUrl := fmt.Sprintf("https://dev.azure.com/%s/%s/_apis/serviceendpoint/endpoints?api-version=7.1-preview.4",
				config.Organization, config.Project)

			endpointsResp, err := makeDevOpsRequest(ctx, logger, http.MethodGet, endpointsUrl, pat)
			if err != nil {
				if strings.Contains(err.Error(), "unauthorized access") {
					logger.Error("Unauthorized access to service endpoints - verify PAT has Service Connections (Read) permissions")
				} else {
					logger.Error("Failed to get service endpoints", slog.String("error", err.Error()))
				}
				continue
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
			if err := json.Unmarshal(body, &endpointsResult); err != nil {
				logger.Error("Failed to parse endpoints", slog.String("error", err.Error()))
				continue
			}

			message.Info("Found %d service endpoints to scan", len(endpointsResult.Value))

			for _, endpoint := range endpointsResult.Value {
				// Filter out sensitive fields
				cleanedData := make(map[string]interface{})
				for k, v := range endpoint.Data {
					if !strings.Contains(strings.ToLower(k), "password") &&
						!strings.Contains(strings.ToLower(k), "secret") &&
						!strings.Contains(strings.ToLower(k), "key") &&
						!strings.Contains(strings.ToLower(k), "token") {
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
					logger.Error("Failed to marshal endpoint content",
						slog.String("error", err.Error()),
						slog.String("endpoint_id", endpoint.Id))
					continue
				}

				out <- types.NpInput{
					Content: string(content),
					Provenance: types.NpProvenance{
						Platform:     "azure-devops",
						ResourceType: "Microsoft.DevOps/ServiceEndpoints",
						ResourceID: fmt.Sprintf("%s/%s/serviceendpoint/%s",
							config.Organization, config.Project, endpoint.Id),
						AccountID: config.Organization,
					},
				}

				// Get endpoint history
				historyUrl := fmt.Sprintf("https://dev.azure.com/%s/%s/_apis/serviceendpoint/%s/executionhistory?api-version=7.1-preview.1",
					config.Organization, config.Project, endpoint.Id)

				historyResp, err := makeDevOpsRequest(ctx, logger, http.MethodGet, historyUrl, pat)
				if err != nil {
					if strings.Contains(err.Error(), "unauthorized access") {
						logger.Error("Unauthorized access to repositories - verify PAT has Code (Read) permissions")
					} else {
						logger.Error("Failed to get endpoint history",
							slog.String("error", err.Error()),
							slog.String("endpoint_id", endpoint.Id))
					}
					continue
				}

				historyBody, err := io.ReadAll(historyResp.Body)
				historyResp.Body.Close()
				if err == nil {
					out <- types.NpInput{
						Content: string(historyBody),
						Provenance: types.NpProvenance{
							Platform:     "azure-devops",
							ResourceType: "Microsoft.DevOps/ServiceEndpoints/History",
							ResourceID: fmt.Sprintf("%s/%s/serviceendpoint/%s/history",
								config.Organization, config.Project, endpoint.Id),
							AccountID: config.Organization,
						},
					}
				}
			}
		}
	}()

	return out
}
