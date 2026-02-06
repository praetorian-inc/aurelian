package recon

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/links/gcp/hierarchy"
	"github.com/praetorian-inc/aurelian/pkg/links/gcp/iam"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"google.golang.org/api/cloudresourcemanager/v1"
)

func init() {
	plugin.Register(&GcpDefaultServiceAccounts{})
}

// GcpDefaultServiceAccounts detects default service accounts with excessive permissions
type GcpDefaultServiceAccounts struct{}

// Metadata methods
func (m *GcpDefaultServiceAccounts) ID() string {
	return "default-service-accounts"
}

func (m *GcpDefaultServiceAccounts) Name() string {
	return "GCP Default Service Account Detection"
}

func (m *GcpDefaultServiceAccounts) Description() string {
	return `Detect default service accounts with excessive permissions across a GCP organization that should be replaced with custom service accounts following least privilege principles.

This module identifies default service accounts in GCP organizations that pose security risks due to their broad permissions:

**Detected Service Account Types:**
- **Compute Engine Default Service Account**: Projects create default service accounts with Editor role for Compute Engine instances
- **App Engine Default Service Account**: App Engine applications use default service accounts with broad permissions
- **Other Default Service Accounts**: Various GCP services create default service accounts with excessive privileges

**Security Risks:**
Default service accounts are created automatically by GCP services and often granted overly broad permissions like the Editor role. These accounts violate the principle of least privilege and should be replaced with custom service accounts that have only the minimum permissions required for their specific function.

**Detection Method:**
1. Enumerates all projects in the specified GCP organization
2. Extracts IAM policies from each accessible project
3. Identifies default service accounts in IAM policy bindings with risky roles
4. Reports violations with service account details, associated projects, and risk assessment

**Remediation:**
Replace default service accounts with custom service accounts that have:
- Specific, minimal IAM roles instead of broad roles like Editor
- Custom names that reflect their purpose
- Regular access reviews and rotation schedules

The module provides detailed findings including risk scoring and specific remediation guidance for each violation.`
}

func (m *GcpDefaultServiceAccounts) Platform() plugin.Platform {
	return plugin.PlatformGCP
}

func (m *GcpDefaultServiceAccounts) Category() plugin.Category {
	return plugin.CategoryRecon
}

func (m *GcpDefaultServiceAccounts) OpsecLevel() string {
	return "low"
}

func (m *GcpDefaultServiceAccounts) Authors() []string {
	return []string{"Praetorian"}
}

func (m *GcpDefaultServiceAccounts) References() []string {
	return []string{
		"https://cloud.google.com/iam/docs/service-accounts#default",
		"https://cloud.google.com/resource-manager/docs/organization-policy/restricting-service-accounts#disable_service_account_default_grants",
		"https://cloud.google.com/compute/docs/access/service-accounts#default_service_account",
	}
}

func (m *GcpDefaultServiceAccounts) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		{
			Name:        "org",
			Description: "GCP organization name or ID",
			Type:        "string",
			Required:    true,
		},
		{
			Name:        "include-sys-projects",
			Description: "include system projects from analysis",
			Type:        "bool",
			Required:    false,
			Default:     true,
		},
	}
}

// Run executes the default service accounts detection module
func (m *GcpDefaultServiceAccounts) Run(cfg plugin.Config) ([]plugin.Result, error) {
	// Get organization parameter
	orgName, ok := cfg.Args["org"].(string)
	if !ok || orgName == "" {
		return nil, fmt.Errorf("org parameter is required")
	}

	// Get optional parameters
	includeSysProjects, _ := cfg.Args["include-sys-projects"].(bool)

	// Initialize context if not provided
	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}

	// Phase 1: Get organization info
	orgInfoLink := hierarchy.NewGcpOrgInfoLink(cfg.Args)
	orgResults, err := orgInfoLink.Process(ctx, orgName)
	if err != nil {
		return nil, fmt.Errorf("failed to get organization info: %w", err)
	}
	if len(orgResults) == 0 {
		return nil, fmt.Errorf("no organization found for: %s", orgName)
	}

	orgResource, ok := orgResults[0].(output.CloudResource)
	if !ok {
		return nil, fmt.Errorf("unexpected organization result type: %T", orgResults[0])
	}

	slog.Info("Processing organization", "org", orgResource.ResourceID, "name", orgResource.DisplayName)

	// Phase 2: List projects in organization
	projectListLink := hierarchy.NewGcpOrgProjectListLink(map[string]any{
		"filter-sys-projects": !includeSysProjects, // Invert: if include=true, filter=false
	})
	projectResults, err := projectListLink.Process(ctx, orgResource)
	if err != nil {
		return nil, fmt.Errorf("failed to list projects: %w", err)
	}

	if len(projectResults) == 0 {
		slog.Info("No projects found in organization")
		return []plugin.Result{
			{
				Data: map[string]any{
					"status":            "success",
					"organization":      orgResource.ResourceID,
					"projects_scanned":  0,
					"violations_found":  0,
					"message":           "No projects found in organization",
				},
			},
		}, nil
	}

	slog.Info("Found projects", "count", len(projectResults))

	// Phase 3 & 4: Collect IAM policies and analyze for default service accounts
	violations := []iam.DefaultServiceAccountViolation{}
	projectsProcessed := make(map[string]string)

	for _, projectResult := range projectResults {
		projectResource, ok := projectResult.(output.CloudResource)
		if !ok {
			slog.Warn("Skipping non-CloudResource project result", "type", fmt.Sprintf("%T", projectResult))
			continue
		}

		// Extract IAM policy for project
		policyData, err := m.extractIAMPolicy(ctx, cfg.Args, projectResource)
		if err != nil {
			slog.Error("Failed to extract IAM policy", "project", projectResource.ResourceID, "error", err)
			continue
		}

		projectsProcessed[policyData.ProjectId] = policyData.ProjectName

		// Analyze policy for default service account violations
		projectViolations := m.analyzeDefaultServiceAccounts(policyData)
		violations = append(violations, projectViolations...)
	}

	slog.Info("Analysis complete",
		"projects_scanned", len(projectsProcessed),
		"violations_found", len(violations))

	// Generate summary
	summary := m.calculateSummary(violations, projectsProcessed)

	// Build result
	result := map[string]any{
		"status":       "success",
		"organization": orgResource.ResourceID,
		"org_name":     orgResource.DisplayName,
		"finding_data": map[string]any{
			"title":           "GCP Default Service Account Violations",
			"attack_category": "Privilege Escalation",
		},
		"violations": violations,
		"summary":    summary,
	}

	return []plugin.Result{
		{
			Data: result,
			Metadata: map[string]any{
				"module":      "default-service-accounts",
				"platform":    "gcp",
				"category":    "recon",
				"opsec_level": "low",
			},
		},
	}, nil
}

// extractIAMPolicy gets the IAM policy for a project
func (m *GcpDefaultServiceAccounts) extractIAMPolicy(ctx context.Context, args map[string]any, projectResource output.CloudResource) (*iam.IAMPolicyData, error) {
	// Create resource manager service
	resourceManagerService, err := cloudresourcemanager.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource manager service: %w", err)
	}

	projectId := projectResource.ResourceID
	policy, err := resourceManagerService.Projects.GetIamPolicy(projectId, &cloudresourcemanager.GetIamPolicyRequest{}).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get IAM policy for project %s: %w", projectId, err)
	}

	return &iam.IAMPolicyData{
		ProjectId:   projectId,
		ProjectName: projectResource.DisplayName,
		Policy:      policy,
		Bindings:    policy.Bindings,
		AccountRef:  projectResource.AccountRef,
	}, nil
}

// Default service account patterns that should be flagged
var defaultServiceAccountPatterns = map[string]string{
	"-compute@developer.gserviceaccount.com": "compute-default",
	"@appspot.gserviceaccount.com":           "appengine-default",
}

// analyzeDefaultServiceAccounts checks IAM policy for default service account violations
func (m *GcpDefaultServiceAccounts) analyzeDefaultServiceAccounts(policyData *iam.IAMPolicyData) []iam.DefaultServiceAccountViolation {
	violations := []iam.DefaultServiceAccountViolation{}

	for _, binding := range policyData.Bindings {
		for _, member := range binding.Members {
			if m.isDefaultServiceAccount(member) {
				// Check if this default service account has risky roles
				if m.hasRiskyRole(binding.Role) {
					violation := iam.DefaultServiceAccountViolation{
						ServiceAccountEmail: member,
						ServiceAccountType:  m.categorizeDefaultServiceAccount(member),
						ProjectId:           policyData.ProjectId,
						ProjectName:         policyData.ProjectName,
						Roles:               []string{binding.Role},
						RiskLevel:           m.determineRiskLevelFromRole(binding.Role),
						Description:         m.generateDescriptionFromRole(member, binding.Role),
						IsActive:            true, // Assume active if it has IAM bindings
					}

					violations = append(violations, violation)
					slog.Debug("Found default service account violation",
						"sa_email", member,
						"project", policyData.ProjectId,
						"role", binding.Role,
						"type", violation.ServiceAccountType)
				}
			}
		}
	}

	return violations
}

// calculateSummary generates summary statistics
func (m *GcpDefaultServiceAccounts) calculateSummary(violations []iam.DefaultServiceAccountViolation, projectsProcessed map[string]string) iam.DefaultServiceAccountSummary {
	summary := iam.DefaultServiceAccountSummary{
		TotalViolations:  len(violations),
		ProjectsAffected: len(projectsProcessed),
	}

	for _, violation := range violations {
		switch violation.ServiceAccountType {
		case "compute-default":
			summary.ComputeDefaultSAs++
		case "appengine-default":
			summary.AppEngineDefaultSAs++
		}

		if violation.IsActive {
			summary.ActiveServiceAccounts++
		}
	}

	return summary
}

// Helper functions

func (m *GcpDefaultServiceAccounts) isDefaultServiceAccount(member string) bool {
	// Handle serviceAccount: prefix
	email := member
	if strings.HasPrefix(member, "serviceAccount:") {
		email = strings.TrimPrefix(member, "serviceAccount:")
	}

	for pattern := range defaultServiceAccountPatterns {
		if strings.Contains(email, pattern) {
			return true
		}
	}
	return false
}

func (m *GcpDefaultServiceAccounts) categorizeDefaultServiceAccount(member string) string {
	// Handle serviceAccount: prefix
	email := member
	if strings.HasPrefix(member, "serviceAccount:") {
		email = strings.TrimPrefix(member, "serviceAccount:")
	}

	for pattern, saType := range defaultServiceAccountPatterns {
		if strings.Contains(email, pattern) {
			return saType
		}
	}
	return "unknown-default"
}

func (m *GcpDefaultServiceAccounts) hasRiskyRole(role string) bool {
	// Flag roles that give broad permissions
	riskyRoles := []string{
		"roles/owner",
		"roles/editor",
		"roles/viewer", // Even viewer can be risky for default SAs
	}

	for _, riskyRole := range riskyRoles {
		if role == riskyRole {
			return true
		}
	}
	return false
}

func (m *GcpDefaultServiceAccounts) determineRiskLevelFromRole(role string) string {
	switch role {
	case "roles/owner", "roles/editor":
		return "high"
	case "roles/viewer":
		return "medium"
	default:
		return "low"
	}
}

func (m *GcpDefaultServiceAccounts) generateDescriptionFromRole(member, role string) string {
	email := member
	if strings.HasPrefix(member, "serviceAccount:") {
		email = strings.TrimPrefix(member, "serviceAccount:")
	}

	saType := m.categorizeDefaultServiceAccount(member)
	switch saType {
	case "compute-default":
		return fmt.Sprintf("Default Compute Engine service account (%s) has %s role which provides broad permissions and should be replaced with a custom service account with minimal permissions", email, role)
	case "appengine-default":
		return fmt.Sprintf("Default App Engine service account (%s) has %s role which provides broad permissions and should be replaced with a custom service account with minimal permissions", email, role)
	default:
		return fmt.Sprintf("Default service account (%s) has %s role and should be replaced with a custom service account with minimal permissions", email, role)
	}
}
