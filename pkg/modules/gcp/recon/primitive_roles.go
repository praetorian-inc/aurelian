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
	plugin.Register(&GcpPrimitiveRoles{})
}

// GcpPrimitiveRoles detects principals using primitive/basic IAM roles that violate least privilege
type GcpPrimitiveRoles struct{}

// Metadata methods
func (m *GcpPrimitiveRoles) ID() string {
	return "primitive-roles"
}

func (m *GcpPrimitiveRoles) Name() string {
	return "GCP Primitive IAM Roles Detection"
}

func (m *GcpPrimitiveRoles) Description() string {
	return `Detect principals using primitive/basic IAM roles (Owner, Editor, Viewer) across a GCP organization that violate the principle of least privilege.

This module identifies principals in GCP organizations that are assigned primitive/basic IAM roles that violate the principle of least privilege:

**Detected Violations:**
- **roles/owner**: Full administrative access to the project and all resources
- **roles/editor**: Edit access to all resources in the project
- **roles/viewer**: Read-only access to all resources in the project

**Security Impact:**
Primitive roles grant broad permissions across an entire project rather than following least-privilege principles. These roles should be replaced with more specific, granular roles that provide only the minimum permissions necessary for the principal's function.

**Detection Method:**
1. Enumerates all projects in the specified GCP organization
2. Extracts IAM policies from each accessible project
3. Identifies all principals (users, service accounts, groups) assigned primitive roles
4. Reports violations with principal details, role assignments, and risk assessment

The module provides detailed findings including risk scoring and remediation guidance for each violation.`
}

func (m *GcpPrimitiveRoles) Platform() plugin.Platform {
	return plugin.PlatformGCP
}

func (m *GcpPrimitiveRoles) Category() plugin.Category {
	return plugin.CategoryRecon
}

func (m *GcpPrimitiveRoles) OpsecLevel() string {
	return "low"
}

func (m *GcpPrimitiveRoles) Authors() []string {
	return []string{"Praetorian"}
}

func (m *GcpPrimitiveRoles) References() []string {
	return []string{
		"https://cloud.google.com/iam/docs/understanding-roles#basic",
		"https://cloud.google.com/iam/docs/using-iam-securely#least_privilege",
	}
}

func (m *GcpPrimitiveRoles) Parameters() []plugin.Parameter {
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
		{
			Name:        "exclude-default-service-accounts",
			Description: "exclude default service accounts from primitive role detection",
			Type:        "bool",
			Required:    false,
			Default:     false,
		},
	}
}

// Run executes the primitive roles detection module
func (m *GcpPrimitiveRoles) Run(cfg plugin.Config) ([]plugin.Result, error) {
	// Get organization parameter
	orgName, ok := cfg.Args["org"].(string)
	if !ok || orgName == "" {
		return nil, fmt.Errorf("org parameter is required")
	}

	// Get optional parameters
	includeSysProjects, _ := cfg.Args["include-sys-projects"].(bool)
	excludeDefaultServiceAccounts, _ := cfg.Args["exclude-default-service-accounts"].(bool)

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

	// Phase 3 & 4: Collect IAM policies and analyze for primitive roles
	violations := []iam.PrimitiveRoleViolation{}
	projectsProcessed := make(map[string]string)

	for _, projectResult := range projectResults {
		projectResource, ok := projectResult.(output.CloudResource)
		if !ok {
			slog.Warn("Skipping non-CloudResource project result", "type", fmt.Sprintf("%T", projectResult))
			continue
		}

		// Extract IAM policy for project (using GCP API directly)
		policyData, err := m.extractIAMPolicy(ctx, cfg.Args, projectResource)
		if err != nil {
			slog.Error("Failed to extract IAM policy", "project", projectResource.ResourceID, "error", err)
			continue
		}

		projectsProcessed[policyData.ProjectId] = policyData.ProjectName

		// Analyze policy for primitive role violations
		projectViolations := m.analyzePrimitiveRoles(policyData, excludeDefaultServiceAccounts)
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
			"title":           "GCP Primitive IAM Roles Violations",
			"attack_category": "Privilege Escalation",
		},
		"violations": violations,
		"summary":    summary,
	}

	return []plugin.Result{
		{
			Data: result,
			Metadata: map[string]any{
				"module":      "primitive-roles",
				"platform":    "gcp",
				"category":    "recon",
				"opsec_level": "low",
			},
		},
	}, nil
}

// extractIAMPolicy gets the IAM policy for a project
func (m *GcpPrimitiveRoles) extractIAMPolicy(ctx context.Context, args map[string]any, projectResource output.CloudResource) (*iam.IAMPolicyData, error) {
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

// Primitive/basic roles that violate least privilege principle
var primitiveRoles = map[string]string{
	"roles/owner":  "Owner",
	"roles/editor": "Editor",
	"roles/viewer": "Viewer",
}

// analyzePrimitiveRoles checks IAM policy for primitive role violations
func (m *GcpPrimitiveRoles) analyzePrimitiveRoles(policyData *iam.IAMPolicyData, excludeDefaultServiceAccounts bool) []iam.PrimitiveRoleViolation {
	violations := []iam.PrimitiveRoleViolation{}

	for _, binding := range policyData.Bindings {
		// Check for primitive roles violations
		roleName, isPrimitiveRole := primitiveRoles[binding.Role]
		if !isPrimitiveRole {
			continue
		}

		for _, member := range binding.Members {
			principalType := m.categorizePrincipal(member)

			// Skip default service accounts if exclusion is enabled
			if excludeDefaultServiceAccounts && principalType == "service_account" && m.isDefaultServiceAccount(member) {
				slog.Debug("Skipping default service account due to exclusion flag", "principal", member)
				continue
			}

			violation := iam.PrimitiveRoleViolation{
				Principal:     member,
				PrincipalType: principalType,
				ProjectId:     policyData.ProjectId,
				ProjectName:   policyData.ProjectName,
				Role:          binding.Role,
				RoleName:      roleName,
				RiskLevel:     m.determineRiskLevel(binding.Role),
				Description:   fmt.Sprintf("Principal has primitive role '%s' (%s) which violates least privilege principle", binding.Role, roleName),
			}

			violations = append(violations, violation)
			slog.Debug("Found primitive role violation",
				"principal", member,
				"role", binding.Role,
				"project", policyData.ProjectId)
		}
	}

	return violations
}

// calculateSummary generates summary statistics
func (m *GcpPrimitiveRoles) calculateSummary(violations []iam.PrimitiveRoleViolation, projectsProcessed map[string]string) iam.PrimitiveRolesSummary {
	summary := iam.PrimitiveRolesSummary{
		TotalViolations:  len(violations),
		ProjectsAffected: len(projectsProcessed),
	}

	for _, violation := range violations {
		switch violation.Role {
		case "roles/owner":
			summary.OwnerRoles++
		case "roles/editor":
			summary.EditorRoles++
		case "roles/viewer":
			summary.ViewerRoles++
		}
	}

	return summary
}

// Helper functions

func (m *GcpPrimitiveRoles) determineRiskLevel(role string) string {
	switch role {
	case "roles/owner", "roles/editor":
		return "high"
	case "roles/viewer":
		return "medium"
	default:
		return "low"
	}
}

func (m *GcpPrimitiveRoles) categorizePrincipal(member string) string {
	if strings.HasPrefix(member, "user:") {
		return "user"
	}
	if strings.HasPrefix(member, "serviceAccount:") {
		return "service_account"
	}
	if strings.HasPrefix(member, "group:") {
		return "group"
	}
	if member == "allUsers" || member == "allAuthenticatedUsers" {
		return "public"
	}
	return "unknown"
}

func (m *GcpPrimitiveRoles) isDefaultServiceAccount(member string) bool {
	// Extract email from serviceAccount:EMAIL format
	email := strings.TrimPrefix(member, "serviceAccount:")

	// Default compute service account pattern: PROJECT_NUMBER-compute@developer.gserviceaccount.com
	// Default App Engine service account pattern: PROJECT_ID@appspot.gserviceaccount.com
	return strings.HasSuffix(email, "-compute@developer.gserviceaccount.com") ||
		strings.HasSuffix(email, "@appspot.gserviceaccount.com")
}
