package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"archive/zip"
	"bytes"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
	"google.golang.org/api/cloudfunctions/v1"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/option"
)

func init() {
	plugin.Register(&ScanFunctionsModule{})
}

// ScanFunctionsModule lists all Cloud Functions in a GCP project and scans them for secrets
type ScanFunctionsModule struct{}

func (m *ScanFunctionsModule) ID() string {
	return "functions-secrets"
}

func (m *ScanFunctionsModule) Name() string {
	return "GCP Scan Functions Secrets"
}

func (m *ScanFunctionsModule) Description() string {
	return "List all Cloud Functions in a GCP project and scan them for secrets."
}

func (m *ScanFunctionsModule) Platform() plugin.Platform {
	return plugin.PlatformGCP
}

func (m *ScanFunctionsModule) Category() plugin.Category {
	return plugin.CategorySecrets
}

func (m *ScanFunctionsModule) OpsecLevel() string {
	return "moderate"
}

func (m *ScanFunctionsModule) Authors() []string {
	return []string{"Praetorian"}
}

func (m *ScanFunctionsModule) References() []string {
	return []string{}
}

func (m *ScanFunctionsModule) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		{
			Name:        "project",
			Description: "GCP Project ID",
			Type:        "string",
			Required:    true,
		},
		{
			Name:        "credentials-file",
			Description: "Path to GCP credentials JSON file",
			Type:        "string",
			Required:    false,
		},
	}
}

func (m *ScanFunctionsModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
	// Get project parameter
	projectID, ok := cfg.Args["project"].(string)
	if !ok || projectID == "" {
		return nil, fmt.Errorf("project parameter is required")
	}

	// Build client options
	var clientOpts []option.ClientOption
	if credsFile, ok := cfg.Args["credentials-file"].(string); ok && credsFile != "" {
		clientOpts = append(clientOpts, option.WithCredentialsFile(credsFile))
	}

	// Get project info
	projectInfo, err := m.getProjectInfo(cfg.Context, projectID, clientOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to get project info: %w", err)
	}

	// List all functions in project
	functions, err := m.listFunctions(cfg.Context, projectID, clientOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to list functions: %w", err)
	}

	if cfg.Verbose {
		fmt.Fprintf(cfg.Output, "Found %d functions in project %s\n", len(functions), projectID)
	}

	// Scan each function for secrets
	var results []plugin.Result
	for _, function := range functions {
		secrets, err := m.scanFunction(cfg.Context, function, projectID, clientOpts)
		if err != nil {
			slog.Error("Failed to scan function", "function", function.Name, "error", err)
			continue
		}

		if len(secrets) > 0 {
			results = append(results, plugin.Result{
				Data: map[string]any{
					"project":        projectID,
					"function":       function.Name,
					"runtime":        function.Runtime,
					"secrets_found":  secrets,
					"project_info":   projectInfo,
				},
				Metadata: map[string]any{
					"module":       "functions-secrets",
					"platform":     "gcp",
					"resource_type": "cloudfunctions.googleapis.com/Function",
				},
			})
		}
	}

	if len(results) == 0 {
		return []plugin.Result{
			{
				Data: map[string]any{
					"status":         "no_secrets_found",
					"project":        projectID,
					"functions_scanned": len(functions),
				},
				Metadata: map[string]any{
					"module":   "functions-secrets",
					"platform": "gcp",
				},
			},
		}, nil
	}

	return results, nil
}

// getProjectInfo retrieves project information
func (m *ScanFunctionsModule) getProjectInfo(ctx context.Context, projectID string, clientOpts []option.ClientOption) (map[string]any, error) {
	resourceManagerService, err := cloudresourcemanager.NewService(ctx, clientOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource manager service: %w", err)
	}

	project, err := resourceManagerService.Projects.Get(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get project %s: %w", projectID, err)
	}

	return map[string]any{
		"name":           project.Name,
		"project_number": project.ProjectNumber,
		"lifecycle_state": project.LifecycleState,
		"parent_type":    project.Parent.Type,
		"parent_id":      project.Parent.Id,
		"labels":         project.Labels,
	}, nil
}

// listFunctions lists all cloud functions in the project
func (m *ScanFunctionsModule) listFunctions(ctx context.Context, projectID string, clientOpts []option.ClientOption) ([]*cloudfunctions.CloudFunction, error) {
	functionsService, err := cloudfunctions.NewService(ctx, clientOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create cloud functions service: %w", err)
	}

	parent := fmt.Sprintf("projects/%s/locations/%s", projectID, "-")
	var functions []*cloudfunctions.CloudFunction

	listReq := functionsService.Projects.Locations.Functions.List(parent)
	err = listReq.Pages(ctx, func(page *cloudfunctions.ListFunctionsResponse) error {
		for _, function := range page.Functions {
			slog.Debug("Found function", "function", function.Name)
			functions = append(functions, function)
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to list functions: %w", err)
	}

	return functions, nil
}

// scanFunction scans a function for secrets
func (m *ScanFunctionsModule) scanFunction(ctx context.Context, function *cloudfunctions.CloudFunction, projectID string, clientOpts []option.ClientOption) ([]types.NpInput, error) {
	var secrets []types.NpInput

	// Scan environment variables
	if len(function.EnvironmentVariables) > 0 {
		content, err := json.Marshal(function.EnvironmentVariables)
		if err == nil {
			secrets = append(secrets, types.NpInput{
				Content: string(content),
				Provenance: types.NpProvenance{
					Platform:     "gcp",
					ResourceType: "cloudfunctions.googleapis.com/Function::EnvVariables",
					ResourceID:   function.Name,
					AccountID:    projectID,
				},
			})
		}
	}

	// Scan source code if available
	if function.SourceArchiveUrl != "" {
		sourceSecrets, err := m.scanFunctionSourceCode(function.SourceArchiveUrl, function.Name, projectID)
		if err != nil {
			slog.Error("Failed to scan function source code", "error", err, "function", function.Name)
		} else {
			secrets = append(secrets, sourceSecrets...)
		}
	}

	return secrets, nil
}

// scanFunctionSourceCode downloads and scans function source code
func (m *ScanFunctionsModule) scanFunctionSourceCode(sourceArchiveUrl, functionName, projectID string) ([]types.NpInput, error) {
	resp, err := http.Get(sourceArchiveUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to download source archive: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to download source archive: status %d", resp.StatusCode)
	}

	archiveData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read archive data: %w", err)
	}

	return m.extractAndScanZipFiles(archiveData, functionName, projectID)
}

// extractAndScanZipFiles extracts files from zip archive and returns content for scanning
func (m *ScanFunctionsModule) extractAndScanZipFiles(archiveData []byte, functionName, projectID string) ([]types.NpInput, error) {
	reader, err := zip.NewReader(bytes.NewReader(archiveData), int64(len(archiveData)))
	if err != nil {
		return nil, fmt.Errorf("failed to create zip reader: %w", err)
	}

	var secrets []types.NpInput

	for _, file := range reader.File {
		if file.FileInfo().IsDir() || m.isSkippableFile(file.Name) {
			continue
		}

		// Skip files larger than 1MB
		if file.UncompressedSize64 > 1*1024*1024 {
			continue
		}

		rc, err := file.Open()
		if err != nil {
			slog.Error("Failed to open file in archive", "file", file.Name, "error", err)
			continue
		}

		content, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			slog.Error("Failed to read file content", "file", file.Name, "error", err)
			continue
		}

		secrets = append(secrets, types.NpInput{
			Content: string(content),
			Provenance: types.NpProvenance{
				Platform:     "gcp",
				ResourceType: "cloudfunctions.googleapis.com/Function::SourceCode",
				ResourceID:   fmt.Sprintf("%s/%s", functionName, file.Name),
				AccountID:    projectID,
			},
		})
	}

	return secrets, nil
}

// isSkippableFile determines if a file should be skipped based on extension
func (m *ScanFunctionsModule) isSkippableFile(filename string) bool {
	binaryExtensions := []string{
		".exe", ".dll", ".so", ".dylib", ".bin", ".jar", ".war", ".ear",
		".zip", ".tar", ".gz", ".bz2", ".rar", ".7z",
		".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp",
		".mp3", ".wav", ".mp4", ".avi", ".mov", ".mkv",
		".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
		".pyc", ".pyo", ".class", ".o", ".obj",
	}
	lowerFilename := strings.ToLower(filename)
	for _, ext := range binaryExtensions {
		if strings.HasSuffix(lowerFilename, ext) {
			return true
		}
	}
	return false
}
