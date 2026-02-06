package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/titus/pkg/scanner"
	"github.com/praetorian-inc/titus/pkg/types"
)

type DevOpsSecretsModule struct{}

func init() {
	plugin.Register(&DevOpsSecretsModule{})
}

func (m *DevOpsSecretsModule) ID() string {
	return "devops-secrets"
}

func (m *DevOpsSecretsModule) Name() string {
	return "Azure DevOps Secret Scanner"
}

func (m *DevOpsSecretsModule) Description() string {
	return "Scans Azure DevOps organizations for secrets in repositories, variable groups, pipelines, and service endpoints using NoseyParker."
}

func (m *DevOpsSecretsModule) Platform() plugin.Platform {
	return plugin.PlatformAzure
}

func (m *DevOpsSecretsModule) Category() plugin.Category {
	return plugin.CategoryRecon
}

func (m *DevOpsSecretsModule) OpsecLevel() string {
	return "moderate"
}

func (m *DevOpsSecretsModule) Authors() []string {
	return []string{"Praetorian"}
}

func (m *DevOpsSecretsModule) References() []string {
	return []string{
		"https://docs.microsoft.com/en-us/azure/devops/",
		"https://github.com/praetorian-inc/noseyparker",
	}
}

func (m *DevOpsSecretsModule) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		{
			Name:        "devops-pat",
			Description: "Azure DevOps Personal Access Token",
			Type:        "string",
			Required:    true,
			Shortcode:   "p",
		},
		{
			Name:        "devops-org",
			Description: "Azure DevOps Organization name",
			Type:        "string",
			Required:    true,
			Shortcode:   "o",
		},
		{
			Name:        "project",
			Description: "Azure DevOps Project (optional, scans all if not specified)",
			Type:        "string",
			Required:    false,
			Shortcode:   "P",
		},
		{
			Name:        "output-file",
			Description: "Output file path for findings",
			Type:        "string",
			Required:    false,
			Default:     "devops-secrets-findings.json",
			Shortcode:   "f",
		},
		{
			Name:        "verbose",
			Description: "Enable verbose logging",
			Type:        "bool",
			Required:    false,
			Default:     false,
			Shortcode:   "v",
		},
	}
}

func (m *DevOpsSecretsModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
	// Validate required arguments
	pat, ok := cfg.Args["devops-pat"].(string)
	if !ok || pat == "" {
		return nil, fmt.Errorf("devops-pat is required")
	}

	org, ok := cfg.Args["devops-org"].(string)
	if !ok || org == "" {
		return nil, fmt.Errorf("devops-org is required")
	}

	project, _ := cfg.Args["project"].(string)
	outputFile, _ := cfg.Args["output-file"].(string)
	if outputFile == "" {
		outputFile = "devops-secrets-findings.json"
	}

	verbose := cfg.Verbose
	if v, ok := cfg.Args["verbose"].(bool); ok {
		verbose = v
	}

	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}

	// Create output writer
	output := cfg.Output
	if output == nil {
		output = os.Stdout
	}

	if verbose {
		fmt.Fprintf(output, "[devops-secrets] Starting scan for organization: %s\n", org)
		if project != "" {
			fmt.Fprintf(output, "[devops-secrets] Targeting project: %s\n", project)
		}
	}

	// Run the secret scan
	findings, err := m.scanDevOpsSecrets(ctx, pat, org, project, verbose, output)
	if err != nil {
		return nil, fmt.Errorf("scan failed: %w", err)
	}

	// Write findings to file
	if err := m.writeFindings(findings, outputFile); err != nil {
		return nil, fmt.Errorf("failed to write findings: %w", err)
	}

	if verbose {
		fmt.Fprintf(output, "[devops-secrets] Scan complete. Found %d secrets. Results written to %s\n", len(findings), outputFile)
	}

	return []plugin.Result{
		{
			Data: map[string]any{
				"organization": org,
				"project":      project,
				"findings":     findings,
				"output_file":  outputFile,
			},
			Metadata: map[string]any{
				"module":      m.ID(),
				"total_findings": len(findings),
			},
		},
	}, nil
}

type SecretFinding struct {
	Source      string `json:"source"`       // repo, variable_group, pipeline, service_endpoint
	SourceID    string `json:"source_id"`    // ID of the source
	SourceName  string `json:"source_name"`  // Name of the source
	SecretType  string `json:"secret_type"`  // Type detected by NoseyParker
	SecretValue string `json:"secret_value"` // Redacted secret value
	Location    string `json:"location"`     // Specific location within source
}

func (m *DevOpsSecretsModule) scanDevOpsSecrets(ctx context.Context, pat, org, project string, verbose bool, output io.Writer) ([]SecretFinding, error) {
	var findings []SecretFinding

	// 1. Scan repositories
	repoFindings, err := m.scanRepositories(ctx, pat, org, project, verbose, output)
	if err != nil {
		if verbose {
			fmt.Fprintf(output, "[devops-secrets] Repository scan error: %v\n", err)
		}
	} else {
		findings = append(findings, repoFindings...)
	}

	// 2. Scan variable groups
	vgFindings, err := m.scanVariableGroups(ctx, pat, org, project, verbose, output)
	if err != nil {
		if verbose {
			fmt.Fprintf(output, "[devops-secrets] Variable group scan error: %v\n", err)
		}
	} else {
		findings = append(findings, vgFindings...)
	}

	// 3. Scan pipelines
	pipelineFindings, err := m.scanPipelines(ctx, pat, org, project, verbose, output)
	if err != nil {
		if verbose {
			fmt.Fprintf(output, "[devops-secrets] Pipeline scan error: %v\n", err)
		}
	} else {
		findings = append(findings, pipelineFindings...)
	}

	// 4. Scan service endpoints
	seFindings, err := m.scanServiceEndpoints(ctx, pat, org, project, verbose, output)
	if err != nil {
		if verbose {
			fmt.Fprintf(output, "[devops-secrets] Service endpoint scan error: %v\n", err)
		}
	} else {
		findings = append(findings, seFindings...)
	}

	return findings, nil
}

func (m *DevOpsSecretsModule) scanRepositories(ctx context.Context, pat, org, project string, verbose bool, output io.Writer) ([]SecretFinding, error) {
	if verbose {
		fmt.Fprintf(output, "[devops-secrets] Scanning repositories...\n")
	}

	// Create temp directory for cloning
	tmpDir, err := os.MkdirTemp("", "devops-repo-scan-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// List repositories
	repos, err := m.listRepositories(ctx, pat, org, project)
	if err != nil {
		return nil, fmt.Errorf("failed to list repositories: %w", err)
	}

	var findings []SecretFinding
	for _, repo := range repos {
		if verbose {
			fmt.Fprintf(output, "[devops-secrets] Scanning repository: %s\n", repo["name"])
		}

		// Clone repository
		repoURL := fmt.Sprintf("https://%s@dev.azure.com/%s/%s/_git/%s",
			pat, org, repo["project"], repo["name"])
		repoPath := filepath.Join(tmpDir, repo["name"].(string))

		cmd := exec.CommandContext(ctx, "git", "clone", "--depth=1", repoURL, repoPath)
		if err := cmd.Run(); err != nil {
			if verbose {
				fmt.Fprintf(output, "[devops-secrets] Failed to clone %s: %v\n", repo["name"], err)
			}
			continue
		}

		// Scan with NoseyParker
		repoFindings, err := m.runNoseyParker(ctx, repoPath, verbose, output)
		if err != nil {
			if verbose {
				fmt.Fprintf(output, "[devops-secrets] NoseyParker scan failed for %s: %v\n", repo["name"], err)
			}
			continue
		}

		// Convert to SecretFinding format
		for _, finding := range repoFindings {
			findings = append(findings, SecretFinding{
				Source:      "repository",
				SourceID:    repo["id"].(string),
				SourceName:  repo["name"].(string),
				SecretType:  finding["rule"].(string),
				SecretValue: "[REDACTED]",
				Location:    finding["location"].(string),
			})
		}
	}

	return findings, nil
}

func (m *DevOpsSecretsModule) scanVariableGroups(ctx context.Context, pat, org, project string, verbose bool, output io.Writer) ([]SecretFinding, error) {
	if verbose {
		fmt.Fprintf(output, "[devops-secrets] Scanning variable groups...\n")
	}

	// List variable groups using Azure DevOps REST API
	vgs, err := m.listVariableGroups(ctx, pat, org, project)
	if err != nil {
		return nil, fmt.Errorf("failed to list variable groups: %w", err)
	}

	var findings []SecretFinding
	for _, vg := range vgs {
		if verbose {
			fmt.Fprintf(output, "[devops-secrets] Scanning variable group: %s\n", vg["name"])
		}

		// Scan variable values with NoseyParker
		variables := vg["variables"].(map[string]any)
		for varName, varData := range variables {
			varMap := varData.(map[string]any)
			if isSecret, ok := varMap["isSecret"].(bool); ok && isSecret {
				findings = append(findings, SecretFinding{
					Source:      "variable_group",
					SourceID:    fmt.Sprintf("%v", vg["id"]),
					SourceName:  vg["name"].(string),
					SecretType:  "Azure DevOps Secret Variable",
					SecretValue: "[REDACTED]",
					Location:    varName,
				})
			}
		}
	}

	return findings, nil
}

func (m *DevOpsSecretsModule) scanPipelines(ctx context.Context, pat, org, project string, verbose bool, output io.Writer) ([]SecretFinding, error) {
	if verbose {
		fmt.Fprintf(output, "[devops-secrets] Scanning pipelines...\n")
	}

	// List pipelines
	pipelines, err := m.listPipelines(ctx, pat, org, project)
	if err != nil {
		return nil, fmt.Errorf("failed to list pipelines: %w", err)
	}

	var findings []SecretFinding
	for _, pipeline := range pipelines {
		if verbose {
			fmt.Fprintf(output, "[devops-secrets] Scanning pipeline: %s\n", pipeline["name"])
		}

		// Get pipeline YAML and scan for secrets
		yamlContent, err := m.getPipelineYAML(ctx, pat, org, project, pipeline["id"].(string))
		if err != nil {
			if verbose {
				fmt.Fprintf(output, "[devops-secrets] Failed to get YAML for %s: %v\n", pipeline["name"], err)
			}
			continue
		}

		// Scan YAML content with NoseyParker
		yamlFindings, err := m.scanTextWithNoseyParker(ctx, yamlContent, verbose, output)
		if err != nil {
			if verbose {
				fmt.Fprintf(output, "[devops-secrets] NoseyParker scan failed for pipeline %s: %v\n", pipeline["name"], err)
			}
			continue
		}

		for _, finding := range yamlFindings {
			findings = append(findings, SecretFinding{
				Source:      "pipeline",
				SourceID:    pipeline["id"].(string),
				SourceName:  pipeline["name"].(string),
				SecretType:  finding["rule"].(string),
				SecretValue: "[REDACTED]",
				Location:    finding["location"].(string),
			})
		}
	}

	return findings, nil
}

func (m *DevOpsSecretsModule) scanServiceEndpoints(ctx context.Context, pat, org, project string, verbose bool, output io.Writer) ([]SecretFinding, error) {
	if verbose {
		fmt.Fprintf(output, "[devops-secrets] Scanning service endpoints...\n")
	}

	// List service endpoints
	endpoints, err := m.listServiceEndpoints(ctx, pat, org, project)
	if err != nil {
		return nil, fmt.Errorf("failed to list service endpoints: %w", err)
	}

	var findings []SecretFinding
	for _, endpoint := range endpoints {
		if verbose {
			fmt.Fprintf(output, "[devops-secrets] Scanning service endpoint: %s\n", endpoint["name"])
		}

		// Service endpoints with credentials
		if auth, ok := endpoint["authorization"].(map[string]any); ok {
			if scheme, ok := auth["scheme"].(string); ok {
				findings = append(findings, SecretFinding{
					Source:      "service_endpoint",
					SourceID:    endpoint["id"].(string),
					SourceName:  endpoint["name"].(string),
					SecretType:  fmt.Sprintf("Service Connection (%s)", scheme),
					SecretValue: "[REDACTED]",
					Location:    "authorization",
				})
			}
		}
	}

	return findings, nil
}

func (m *DevOpsSecretsModule) runNoseyParker(ctx context.Context, path string, verbose bool, output io.Writer) ([]map[string]any, error) {
	// Read file content
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Create scanner with builtin rules
	core, err := scanner.NewCore("builtin", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create scanner: %w", err)
	}
	defer core.Close()

	// Scan content
	result, err := core.Scan(string(content), path)
	if err != nil {
		return nil, fmt.Errorf("scan failed: %w", err)
	}

	// Convert result.Matches to existing []map[string]any format
	var results []map[string]any
	for _, match := range result.Matches {
		results = append(results, m.convertMatchToMap(match))
	}

	return results, nil
}

func (m *DevOpsSecretsModule) scanTextWithNoseyParker(ctx context.Context, text string, verbose bool, output io.Writer) ([]map[string]any, error) {
	// Create scanner with builtin rules
	core, err := scanner.NewCore("builtin", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create scanner: %w", err)
	}
	defer core.Close()

	// Scan content directly
	result, err := core.Scan(text, "inline-text")
	if err != nil {
		return nil, fmt.Errorf("scan failed: %w", err)
	}

	// Convert result.Matches to existing []map[string]any format
	var results []map[string]any
	for _, match := range result.Matches {
		results = append(results, m.convertMatchToMap(match))
	}

	return results, nil
}

func (m *DevOpsSecretsModule) listRepositories(ctx context.Context, pat, org, project string) ([]map[string]any, error) {
	// Placeholder: would use Azure DevOps REST API
	// https://dev.azure.com/{organization}/{project}/_apis/git/repositories
	return []map[string]any{}, nil
}

func (m *DevOpsSecretsModule) listVariableGroups(ctx context.Context, pat, org, project string) ([]map[string]any, error) {
	// Placeholder: would use Azure DevOps REST API
	// https://dev.azure.com/{organization}/{project}/_apis/distributedtask/variablegroups
	return []map[string]any{}, nil
}

func (m *DevOpsSecretsModule) listPipelines(ctx context.Context, pat, org, project string) ([]map[string]any, error) {
	// Placeholder: would use Azure DevOps REST API
	// https://dev.azure.com/{organization}/{project}/_apis/pipelines
	return []map[string]any{}, nil
}

func (m *DevOpsSecretsModule) getPipelineYAML(ctx context.Context, pat, org, project, pipelineID string) (string, error) {
	// Placeholder: would use Azure DevOps REST API
	// https://dev.azure.com/{organization}/{project}/_apis/pipelines/{pipelineId}
	return "", nil
}

func (m *DevOpsSecretsModule) listServiceEndpoints(ctx context.Context, pat, org, project string) ([]map[string]any, error) {
	// Placeholder: would use Azure DevOps REST API
	// https://dev.azure.com/{organization}/{project}/_apis/serviceendpoint/endpoints
	return []map[string]any{}, nil
}

func (m *DevOpsSecretsModule) convertMatchToMap(match *types.Match) map[string]any {
	return map[string]any{
		"rule":     match.RuleName,
		"rule_id":  match.RuleID,
		"location": fmt.Sprintf("%d:%d-%d:%d",
			match.Location.Source.Start.Line,
			match.Location.Source.Start.Column,
			match.Location.Source.End.Line,
			match.Location.Source.End.Column,
		),
		"offset_start": match.Location.Offset.Start,
		"offset_end":   match.Location.Offset.End,
		"snippet":      string(match.Snippet.Matching),
		"before":       string(match.Snippet.Before),
		"after":        string(match.Snippet.After),
	}
}

func (m *DevOpsSecretsModule) writeFindings(findings []SecretFinding, outputFile string) error {
	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal findings: %w", err)
	}

	if err := os.WriteFile(outputFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	return nil
}
