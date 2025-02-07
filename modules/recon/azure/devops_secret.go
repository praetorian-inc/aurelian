// devops_secrets.go
package reconaz

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/internal/message"
	op "github.com/praetorian-inc/nebula/internal/output_providers"
	"github.com/praetorian-inc/nebula/modules"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/stages"
	"github.com/praetorian-inc/nebula/pkg/types"
)

var AzureDevOpsSecretsMetadata = modules.Metadata{
	Id:          "devops-secrets",
	Name:        "Azure DevOps Secrets Scanner",
	Description: "Find secrets in Azure DevOps resources including repositories, variable groups, service connections, pipelines, and job logs",
	Platform:    modules.Azure,
	Authors:     []string{"Praetorian"},
	OpsecLevel:  modules.Moderate,
	References: []string{
		"https://learn.microsoft.com/en-us/azure/devops/integrate/get-started/authentication/oauth",
		"https://learn.microsoft.com/en-us/azure/devops/pipelines/library/variable-groups",
		"https://learn.microsoft.com/en-us/azure/devops/pipelines/library/service-endpoints",
		"https://learn.microsoft.com/en-us/azure/devops/pipelines/process/variables",
		"https://learn.microsoft.com/en-us/azure/devops/repos/git/repository-settings",
	},
}

var AzureDevOpsSecretsOptions = []*types.Option{
	&options.AzureDevOpsPATOpt,
	&options.AzureDevOpsOrgOpt,
	&options.NoseyParkerPathOpt,
	&options.NoseyParkerArgsOpt,
	&options.NoseyParkerOutputOpt,
	options.WithDefaultValue(
		*options.WithRequired(options.FileNameOpt, false),
		""),
}

var AzureDevOpsSecretsOutputProviders = []func(options []*types.Option) types.OutputProvider{
	op.NewJsonFileProvider,
	op.NewConsoleProvider,
}

func NewAzureDevOpsSecrets(opts []*types.Option) (<-chan string, stages.Stage[string, string], error) {
	ctx := context.WithValue(context.Background(), "metadata", AzureDevOpsSecretsMetadata)
	logger := logs.NewModuleLogger(ctx, opts)

	// Validate NoseyParker installation
	npPath := options.GetOptionByName(options.NoseyParkerPathOpt.Name, opts).Value

	if _, err := helpers.FindBinary(npPath); err != nil {
		return nil, nil, fmt.Errorf("NoseyParker binary not found at %s: %v", npPath, err)
	}

	if _, err := helpers.FindBinary("git"); err != nil {
		return nil, nil, fmt.Errorf("Git not found in PATH: %v", err)
	}

	// Validate PAT token
	pat := options.GetOptionByName(options.AzureDevOpsPATOpt.Name, opts).Value
	if pat == "" {
		return nil, nil, fmt.Errorf("Azure DevOps PAT token is required")
	}

	// Create temporary directory for Git operations
	tempDir := filepath.Join(os.TempDir(), "azdo-scan-"+uuid.New().String())
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return nil, nil, fmt.Errorf("failed to create temp directory: %v", err)
	}

	// Clean up temp directory when done
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			message.Warning("Failed to clean up temp directory: %v", err)
		}
	}()

	// Create output directory if it doesn't exist
	outputDir := options.GetOptionByName(options.OutputOpt.Name, opts).Value
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, nil, fmt.Errorf("failed to create output directory: %v", err)
	}

	// Create datastore directory if needed
	datastoreDir := filepath.Join(outputDir, options.GetOptionByName(options.NoseyParkerOutputOpt.Name, opts).Value)
	if err := os.MkdirAll(filepath.Dir(datastoreDir), 0755); err != nil {
		return nil, nil, fmt.Errorf("failed to create datastore directory: %v", err)
	}

	organization := options.GetOptionByName(options.AzureDevOpsOrgOpt.Name, opts).Value

	projects, err := stages.GetOrganizationProjects(ctx, logger, pat, organization)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list projects: %v", err)
	}

	message.Info("Found %d projects in organization %s", len(projects), organization)

	// Create input channel with config for each project
	configChan := make(chan string)
	go func() {
		defer close(configChan)
		for _, project := range projects {
			config := types.DevOpsScanConfig{
				Organization: organization,
				Project:      project,
				TempDir:      tempDir,
			}
			if configStr, err := json.Marshal(config); err == nil {
				configChan <- string(configStr)
			}
		}
	}()

	message.Info("Starting Azure DevOps secrets scan")
	message.Info("Organization: %s", options.GetOptionByName(options.AzureDevOpsOrgOpt.Name, opts).Value)
	message.Info("Output directory: %s", outputDir)
	message.Info("NoseyParker datastore: %s", datastoreDir)

	// Create resource pipelines
	var resourcePipelines [][]stages.Stage[string, types.NpInput]

	// Git repos pipeline
	gitPipeline, err := stages.ChainStages[string, types.NpInput](
		stages.AzureDevOpsReposStage,
	)
	if err == nil {
		resourcePipelines = append(resourcePipelines, []stages.Stage[string, types.NpInput]{gitPipeline})
	}

	// Variable groups pipeline
	varsPipeline, err := stages.ChainStages[string, types.NpInput](
		stages.AzureDevOpsVariableGroupsStage,
	)
	if err == nil {
		resourcePipelines = append(resourcePipelines, []stages.Stage[string, types.NpInput]{varsPipeline})
	}

	// Pipelines scanning pipeline
	pipelinesPipeline, err := stages.ChainStages[string, types.NpInput](
		stages.AzureDevOpsPipelinesStage,
	)
	if err == nil {
		resourcePipelines = append(resourcePipelines, []stages.Stage[string, types.NpInput]{pipelinesPipeline})
	}

	// Service endpoints pipeline
	endpointsPipeline, err := stages.ChainStages[string, types.NpInput](
		stages.AzureDevOpsServiceEndpointsStage,
	)
	if err == nil {
		resourcePipelines = append(resourcePipelines, []stages.Stage[string, types.NpInput]{endpointsPipeline})
	}

	// Create final pipeline with parallel scanning
	pipeline, err := stages.ChainStages[string, string](
		stages.Tee(resourcePipelines...),
		stages.NoseyParkerEnumeratorStage,
		stages.NoseyParkerSummarizeStage,
	)

	if err != nil {
		return nil, nil, fmt.Errorf("failed to create pipeline: %v", err)
	}

	return configChan, pipeline, nil
}
